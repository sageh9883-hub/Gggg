/**
 * Sistema de papéis (roles) do painel admin.
 *
 * - 'master'     : acesso total (padrão para contas antigas, sem role definida — compatibilidade).
 * - 'semi_admin' : acesso restrito. Só pode CRIAR licenças. Não pode listar/editar/apagar
 *                  licenças, nem gerenciar outros usuários do painel.
 *
 * Máximo de 2 contas 'semi_admin' simultâneas (imposto em createPanelUser.js).
 *
 * O role fica salvo em user_metadata.role (Supabase Auth). Contas criadas antes deste
 * sistema não têm essa chave — são tratadas como 'master' para não perder acesso.
 */
const { getSupabase } = require('./supabaseClient');

const MAX_SEMI_ADMINS = 2;

/** Busca o usuário completo (com user_metadata) e retorna seu role. */
async function getUserRole(userId) {
    const supabase = getSupabase();
    const { data, error } = await supabase.auth.admin.getUserById(userId);
    if (error || !data || !data.user) return null;
    const role = data.user.user_metadata && data.user.user_metadata.role;
    return role === 'semi_admin' ? 'semi_admin' : 'master';
}

/** true se o usuário autenticado é master (ou conta legada sem role). */
async function isMaster(user) {
    if (!user || !user.id) return false;
    const role = await getUserRole(user.id);
    return role === 'master';
}

/** Conta quantos semi_admin já existem. */
async function countSemiAdmins() {
    const supabase = getSupabase();
    const { data, error } = await supabase.auth.admin.listUsers();
    if (error || !data) return 0;
    return (data.users || []).filter(u => u.user_metadata && u.user_metadata.role === 'semi_admin').length;
}

module.exports = { getUserRole, isMaster, countSemiAdmins, MAX_SEMI_ADMINS };
