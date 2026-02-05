module.exports = async function (context, req) {
  const principalHeader = req.headers['x-ms-client-principal'];
  if (!principalHeader) {
    context.res = { status: 401 }; // 未認証
    return;
  }

  // SWAが付与するヘッダーをデコード
  const decoded = Buffer.from(principalHeader, 'base64').toString('utf8');
  const clientPrincipal = JSON.parse(decoded).clientPrincipal || {};

  // 必要最小限の属性だけ返却（最小権限の原則）
  const roles = Array.isArray(clientPrincipal.userRoles) ? [...new Set(clientPrincipal.userRoles)] : [];
  const claims = Array.isArray(clientPrincipal.claims) ? clientPrincipal.claims : [];

  // よく使うクレーム（name / email / preferred_username / roles）だけ抽出
  const pick = new Set(['name','email','preferred_username','roles']);
  const filteredClaims = claims
    .filter(c => pick.has(c.typ))
    .map(c => ({ type: c.typ, value: c.val }));

  context.res = {
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' },
    body: {
      provider: clientPrincipal.identityProvider,
      userId: clientPrincipal.userId,
      userDetails: clientPrincipal.userDetails, // メール相当
      roles: roles,                               // ["authenticated","Admin"] 等
      claims: filteredClaims
    }
  };
};
