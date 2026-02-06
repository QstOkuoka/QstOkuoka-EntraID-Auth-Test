
// your-repo/api/userinfo/index.js
module.exports = async function (context, req) {
  const enc = req.headers['x-ms-client-principal'];
  if (!enc) { context.res = { status: 401 }; return; }

  const json = Buffer.from(enc, 'base64').toString('utf8');
  const cp = JSON.parse(json).clientPrincipal || {};
  const roles = Array.isArray(cp.userRoles) ? cp.userRoles : [];

  context.res = {
    status: 200,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store, no-cache, must-revalidate",
      "Pragma": "no-cache",
      "Expires": "0"
    },
    body: {
      userId: cp.userId,
      userDetails: cp.userDetails,
      roles
    }
  };
};
