// /api/getRolesForUser/index.js
module.exports = async function (context, req) {
  // 1) SWA が付与するユーザー情報ヘッダーを取得
  const header = req.headers['x-ms-client-principal'];
  if (!header) {
    // 未ログイン等。少なくとも authenticated は SWA 側で自動付与されるが、
    // 明示的に roles を返さない場合は空で返す。
    context.res = { body: { roles: [] } };
    return;
  }

  // 2) Base64 デコード → JSON 変換
  const decoded = Buffer.from(header, 'base64').toString('utf8');
  const clientPrincipal = JSON.parse(decoded);

  // 3) claims から App Roles を抽出（typ が 'roles' または 'role' のクレーム）
  //    テナントや発行方法により typ は 'roles' だったり 'http://schemas.microsoft.com/ws/2008/06/identity/claims/role' の場合もある。
  const claims = clientPrincipal?.claims || [];
  const roleClaims = claims
    .filter(c =>
      c.typ === 'roles' ||
      c.typ === 'role' ||
      c.typ.includes('/identity/claims/role')
    )
    .map(c => c.val);

  // 4) SWA のロールとして返却（Admin / User など、staticwebapp.config.json の allowedRoles と一致させる）
  context.res = {
    body: {
      roles: roleClaims
    }
  };
};
