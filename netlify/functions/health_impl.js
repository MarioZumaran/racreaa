module.exports = function handler(req, res) {
  res.status(200).json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    node: process.version,
    env: {
      has_db:  !!process.env.DATABASE_URL,
      has_jwt: !!process.env.JWT_SECRET,
    }
  });
};
