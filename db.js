
// ============================================================
// 📁 db.js - D1 Database Helper
// ============================================================

export async function query(env, sql, params = []) {
  try {
    const stmt = env.DB.prepare(sql);
    if (params.length > 0) {
      return await stmt.bind(...params).all();
    }
    return await stmt.all();
  } catch (error) {
    console.error('Database error:', error);
    throw error;
  }
}

export async function run(env, sql, params = []) {
  try {
    const stmt = env.DB.prepare(sql);
    if (params.length > 0) {
      return await stmt.bind(...params).run();
    }
    return await stmt.run();
  } catch (error) {
    console.error('Database error:', error);
    throw error;
  }
}
