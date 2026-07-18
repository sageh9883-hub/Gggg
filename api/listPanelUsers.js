const { verifyToken } = require('./_lib/verifyToken');
const { getSupabase } = require('./_lib/supabaseClient');
const { isMaster } = require('./_lib/roles');

function json(res, status, data) {
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.status(status).end(JSON.stringify(data));
}

module.exports = async function handler(req, res) {
    if (req.method === 'OPTIONS') {
        res.setHeader('Access-Control-Allow-Origin', '*');
        res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
        res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Auth-Token');
        return res.status(204).end();
    }
    if (req.method !== 'GET') return json(res, 405, { error: 'Método não permitido' });

    const user = await verifyToken(req);
    if (!user) return json(res, 401, { error: 'Não autorizado.' });

    if (!(await isMaster(user))) {
        return json(res, 403, { error: 'Apenas o administrador master pode listar acessos.' });
    }

    try {
        const supabase = getSupabase();
        const { data, error } = await supabase.auth.admin.listUsers();
        if (error) {
            console.error('[listPanelUsers]', error.message);
            return json(res, 500, { error: 'Erro ao listar usuários.' });
        }

        const users = (data.users || []).map(u => ({
            uid: u.id,
            email: u.email || '',
            displayName: (u.user_metadata && u.user_metadata.display_name) || '',
            role: (u.user_metadata && u.user_metadata.role) === 'semi_admin' ? 'semi_admin' : 'master',
            disabled: u.banned_until ? true : false,
            validUntil: (u.user_metadata && u.user_metadata.valid_until) || null,
            createdAt: u.created_at
        }));

        return json(res, 200, { success: true, users });
    } catch (err) {
        console.error('[listPanelUsers]', err);
        return json(res, 500, { error: 'Erro interno.' });
    }
};
