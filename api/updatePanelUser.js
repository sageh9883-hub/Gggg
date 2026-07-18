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
        res.setHeader('Access-Control-Allow-Methods', 'PATCH, OPTIONS');
        res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Auth-Token');
        return res.status(204).end();
    }
    if (req.method !== 'PATCH') return json(res, 405, { error: 'Método não permitido' });

    const user = await verifyToken(req);
    if (!user) return json(res, 401, { error: 'Não autorizado.' });

    if (!(await isMaster(user))) {
        return json(res, 403, { error: 'Apenas o administrador master pode editar acessos.' });
    }

    const { uid, email, displayName, disabled, validUntil, password } = req.body || {};
    if (!uid) return json(res, 400, { error: 'uid é obrigatório.' });

    try {
        const supabase = getSupabase();

        // Busca o usuário atual para preservar campos de metadata não enviados no PATCH
        // (em especial `role` — sem isso, um edit de nome/validade apagaria o role do semi_admin).
        const { data: existing, error: fetchError } = await supabase.auth.admin.getUserById(uid);
        if (fetchError || !existing || !existing.user) {
            return json(res, 404, { error: 'Usuário não encontrado.' });
        }
        const existingMetadata = existing.user.user_metadata || {};

        const updateData = {};

        if (email) {
            updateData.email = email.trim().toLowerCase();
        }

        if (displayName !== undefined || validUntil !== undefined) {
            updateData.user_metadata = { ...existingMetadata };
            if (displayName !== undefined) updateData.user_metadata.display_name = displayName;
            if (validUntil !== undefined) updateData.user_metadata.valid_until = validUntil;
        }

        if (password) {
            updateData.password = password;
        }

        if (disabled !== undefined) {
            if (disabled) {
                updateData.ban_duration = '876600h'; // ~100 anos
            } else {
                updateData.ban_duration = 'none';
            }
        }

        const { data, error } = await supabase.auth.admin.updateUserById(uid, updateData);

        if (error) {
            console.error('[updatePanelUser]', error.message);
            return json(res, 500, { error: error.message || 'Erro ao atualizar usuário.' });
        }

        return json(res, 200, {
            success: true,
            user: {
                uid: data.user.id,
                email: data.user.email,
                displayName: (data.user.user_metadata && data.user.user_metadata.display_name) || '',
                role: (data.user.user_metadata && data.user.user_metadata.role) === 'semi_admin' ? 'semi_admin' : 'master'
            }
        });
    } catch (err) {
        console.error('[updatePanelUser]', err);
        return json(res, 500, { error: 'Erro interno.' });
    }
};
