// netlify/functions/canvas-proxy.js
//
// ブラウザ -> この Function -> Canvas API
// サーバーサイドからのリクエストなので CORS 制限を受けない。
// Bearer トークンはブラウザから受け取り、Canvas へ転送するだけ（保存しない）。

'use strict';

const dns = require('node:dns').promises;
const net = require('node:net');

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  'Access-Control-Expose-Headers': 'Link',
};

function reply(status, data, extraHeaders = {}) {
  return {
    statusCode: status,
    headers: {
      'Content-Type': 'application/json',
      ...CORS_HEADERS,
      ...extraHeaders,
    },
    body: JSON.stringify(data),
  };
}

function normalizeBaseUrl(canvasUrl) {
  let base = canvasUrl.trim().replace(/\/+$/, '');
  if (!/^https?:\/\//i.test(base)) base = `https://${base}`;
  return base.replace(/\/api\/v1\/?$/i, '');
}

function normalizeApiPath(path) {
  const trimmed = path.trim();
  if (/^https?:\/\//i.test(trimmed) || trimmed.startsWith('//')) {
    return null;
  }
  return trimmed.startsWith('/') ? trimmed : `/${trimmed}`;
}

function normalizeParams(params) {
  if (!params) return '';

  const trimmed = params.trim();
  if (!trimmed) return '';
  if (trimmed.startsWith('?')) return trimmed;
  if (trimmed.startsWith('&')) return `?${trimmed.slice(1)}`;
  return `?${trimmed}`;
}

function isBlockedAddress(address) {
  const host = address.toLowerCase().replace(/^\[|\]$/g, '');

  if (host.startsWith('::ffff:')) {
    return isBlockedAddress(host.slice(7));
  }

  if (net.isIP(host) === 6) {
    if (host === '::' || host === '::1') return true;

    const firstGroup = Number.parseInt(host.split(':')[0], 16);
    if (Number.isNaN(firstGroup)) return false;

    // Unique local fc00::/7 and link-local fe80::/10.
    return (firstGroup & 0xfe00) === 0xfc00 || (firstGroup & 0xffc0) === 0xfe80;
  }

  if (net.isIP(host) !== 4) return false;

  const parts = host.split('.').map(Number);
  const [a, b] = parts;

  return (
    a === 0 ||
    a === 10 ||
    a === 127 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && (b === 0 || b === 168)) ||
    (a === 198 && (b === 18 || b === 19)) ||
    a >= 224
  );
}

async function isBlockedHost(hostname) {
  const host = hostname.toLowerCase().replace(/^\[|\]$/g, '');

  if (
    host === 'localhost' ||
    host.endsWith('.localhost') ||
    host === 'metadata.google.internal'
  ) {
    return true;
  }

  if (net.isIP(host)) return isBlockedAddress(host);

  const records = await dns.lookup(host, { all: true, verbatim: true });
  return records.some((record) => isBlockedAddress(record.address));
}

exports.handler = async (event) => {
  // CORS プリフライトへの応答
  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 200, headers: CORS_HEADERS, body: '' };
  }

  if (event.httpMethod !== 'POST') {
    return reply(405, { error: 'POST メソッドのみ受け付けます' });
  }

  // リクエストボディをパース
  let body;
  try {
    body = JSON.parse(event.body || '{}');
  } catch {
    return reply(400, { error: 'リクエストボディが不正なJSONです' });
  }

  const { canvasUrl, token, path, params = '' } = body;

  if (!canvasUrl || typeof canvasUrl !== 'string') {
    return reply(400, { error: 'canvasUrl が必要です' });
  }
  if (!token || typeof token !== 'string') {
    return reply(400, { error: 'token が必要です' });
  }
  if (!path || typeof path !== 'string') {
    return reply(400, { error: 'path が必要です' });
  }
  if (typeof params !== 'string') {
    return reply(400, { error: 'params は文字列で指定してください' });
  }

  // Canvas URL を正規化
  const base = normalizeBaseUrl(canvasUrl);

  // SSRF 防止: プライベートアドレスへのリクエストを禁止
  let parsedUrl;
  try {
    parsedUrl = new URL(base);
  } catch {
    return reply(400, { error: 'Canvas URL が正しい形式ではありません' });
  }

  if (!['http:', 'https:'].includes(parsedUrl.protocol)) {
    return reply(400, { error: 'Canvas URL は http または https で指定してください' });
  }

  try {
    if (await isBlockedHost(parsedUrl.hostname)) {
      return reply(403, { error: 'プライベートアドレスへのリクエストは禁止されています' });
    }
  } catch (err) {
    return reply(400, {
      error: `Canvas URL のホスト名を解決できません: ${parsedUrl.hostname}\n詳細: ${err.message}`,
    });
  }

  const apiPath = normalizeApiPath(path);
  if (!apiPath) {
    return reply(400, { error: 'path には Canvas API の相対パスを指定してください' });
  }

  // Canvas API エンドポイントを組み立て
  const endpoint = `${base}/api/v1${apiPath}${normalizeParams(params)}`;

  // サーバーサイドから Canvas API を呼び出す（CORS 制限なし）
  let canvasRes;
  try {
    canvasRes = await fetch(endpoint, {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: 'application/json',
        'User-Agent': 'ShitsukoisAlarm-Proxy/2.0',
      },
    });
  } catch (err) {
    return reply(502, {
      error: `Canvas API への接続に失敗しました。\nURL を確認してください: ${base}\n詳細: ${err.message}`,
    });
  }

  // レスポンス本文を取得
  let text;
  try {
    text = await canvasRes.text();
  } catch (err) {
    return reply(502, {
      error: `Canvas レスポンスの読み取りに失敗しました: ${err.message}`,
    });
  }

  // HTML が返ってきた場合（ログインリダイレクト or URL 誤り）
  if (text.trimStart().startsWith('<')) {
    if (canvasRes.status === 401 || canvasRes.redirected) {
      return reply(401, {
        error: [
          'ログインページにリダイレクトされました。',
          'APIトークンが無効か期限切れです。',
          '',
          'Canvas -> Account -> Settings -> Approved Integrations',
          '-> New Access Token で新しいトークンを発行してください。',
        ].join('\n'),
      });
    }
    return reply(502, {
      error: [
        `Canvas が HTML を返しました (HTTP ${canvasRes.status})。`,
        'Canvas URL が正しいか確認してください。',
        `設定中の URL: ${base}`,
        '正しい例: https://university.instructure.com',
      ].join('\n'),
    });
  }

  // Canvas の HTTP エラーステータスに対応するメッセージ
  if (canvasRes.status === 401) {
    return reply(401, {
      error: [
        'APIトークンが無効または期限切れです (401 Unauthorized)。',
        '',
        'Canvas -> Account -> Settings -> Approved Integrations',
        '-> New Access Token で新しいトークンを発行してください。',
      ].join('\n'),
    });
  }
  if (canvasRes.status === 403) {
    return reply(403, {
      error: 'このAPIへのアクセス権がありません (403 Forbidden)。',
    });
  }
  if (canvasRes.status === 404) {
    return reply(404, {
      error: [
        'Canvas API エンドポイントが見つかりません (404)。',
        `リクエスト先: ${endpoint}`,
        'Canvas URL を確認してください。',
      ].join('\n'),
    });
  }
  if (!canvasRes.ok) {
    return reply(canvasRes.status, {
      error: `Canvas API エラー (HTTP ${canvasRes.status})`,
    });
  }

  const responseHeaders = { 'Content-Type': 'application/json', ...CORS_HEADERS };
  const linkHeader = canvasRes.headers.get('link');
  if (linkHeader) responseHeaders.Link = linkHeader;

  // 空レスポンス
  if (!text.trim()) {
    return {
      statusCode: 200,
      headers: responseHeaders,
      body: '[]',
    };
  }

  // 成功: Canvas の JSON レスポンスをそのままブラウザに返す
  return {
    statusCode: 200,
    headers: responseHeaders,
    body: text,
  };
};
