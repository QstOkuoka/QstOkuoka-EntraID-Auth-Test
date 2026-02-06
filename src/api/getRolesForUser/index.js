module.exports = async function (context, req) {
  // 1) SWA が付与するユーザー情報ヘッダーを取得
  const header = req.headers['x-ms-client-principal'];
  if (!header) {
    // 未ログイン等
    context.res = { body: { roles: [] } };
    return;
  }

  // 2) Base64 デコード → JSON へ
  const decoded = Buffer.from(header, 'base64').toString('utf8');
  const clientPrincipal = JSON.parse(decoded);

  // 3) claims からロール系クレームを抽出
  //    AAD の app roles は通常 'roles'（複数形）クレームに入ります。
  //    環境によっては 'role' や schema 付きの typ になることもあるので網羅します。
  const claims = clientPrincipal?.claims || [];
  const roleClaims = claims
    .filter(c =>
      c.typ === 'roles' ||
      c.typ === 'role' ||
      c.typ.includes('/identity/claims/role')
    )
    .map(c => c.val);

  // 4) SWA に返すロール（staticwebapp.config.json の allowedRoles と一致する値にする）
  context.res = {
    body: {
      roles: roleClaims
    }
  };
};
