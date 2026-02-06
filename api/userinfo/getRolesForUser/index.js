module.exports = async function (context, req) {
  // SWA から渡されるユーザー情報ヘッダー
  const header = req.headers['x-ms-client-principal'];

  // 未ログイン等でも 200 と空配列を返す（401 を返さない！）
  if (!header) {
    context.res = { status: 200, body: { roles: [] } };
    return;
  }

  const decoded = Buffer.from(header, 'base64').toString('utf8');
  const clientPrincipal = JSON.parse(decoded);
  const claims = clientPrincipal?.claims || [];

  // AAD の App Roles は多くの環境で "roles" クレーム
  const roleClaims = claims
    .filter(c =>
      c.typ === 'roles' ||
      c.typ === 'role' ||
      c.typ.includes('/identity/claims/role')
    )
    .map(c => c.val);

  // ここで { roles: ["Admin"] } などを返す
  context.res = { status: 200, body: { roles: roleClaims } };
};
