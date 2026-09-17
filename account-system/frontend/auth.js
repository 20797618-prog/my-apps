// 账号体系 · 前端通用认证模块（浏览器端）
// 用法：<script src="auth.js"></script> 后，通过全局对象 AccountAuth 调用。
// 依赖：后端已部署 account-system/backend 到同域 /api/auth/* 接口。
//
// 提供的方法：
//   AccountAuth.requestCode(email)                   发送验证码 -> {ok, dev}
//   AccountAuth.verifyCode(email, code)              校验验证码并登录 -> {token, email, hasPassword, isNewUser}
//   AccountAuth.loginPassword(email, password)       6 位数字密码登录 -> {token, email}
//   AccountAuth.setPassword(password)                设置/修改密码（需已登录）
//   AccountAuth.me()                                 校验当前会话 -> {user}
//   AccountAuth.logout()                             清除本地会话
//   AccountAuth.getToken() / isLoggedIn()            读取会话状态
//
// 会话 token 存于 localStorage（默认键 auth_token），30 天有效，与后端 SESSION_TTL 一致。

(function (global) {
    'use strict';

    // 后端接口前缀：同域部署时留空即可；若账号中心独立部署，改成其域名，如 'https://auth.example.pages.dev'
    var API_BASE = window.AUTH_API_BASE || '';
    // localStorage 键名（不同应用可自定义，避免冲突）
    var TOKEN_KEY = window.AUTH_TOKEN_KEY || 'auth_token';

    function getToken() {
        try { return localStorage.getItem(TOKEN_KEY) || null; } catch (e) { return null; }
    }
    function setToken(token) {
        try { token ? localStorage.setItem(TOKEN_KEY, token) : localStorage.removeItem(TOKEN_KEY); } catch (e) {}
    }

    // 统一请求封装：自动附带 Bearer token，401 抛出带 status 的错误，其余非 2xx 抛业务 message
    async function api(path, options) {
        options = options || {};
        var headers = Object.assign({}, options.headers || {});
        var token = getToken();
        if (token) headers['Authorization'] = 'Bearer ' + token;
        if (options.body !== undefined) headers['Content-Type'] = 'application/json';
        var res = await fetch(API_BASE + path, Object.assign({}, options, { headers: headers }));
        var data = null;
        try { data = await res.json(); } catch (e) {}
        if (res.status === 401) {
            var err401 = new Error((data && data.message) || '登录已过期');
            err401.status = 401;
            throw err401;
        }
        if (!res.ok) {
            var err = new Error((data && data.message) || '请求失败');
            err.status = res.status;
            err.data = data;
            throw err;
        }
        return data;
    }

    var AccountAuth = {
        API_BASE: API_BASE,
        getToken: getToken,
        isLoggedIn: function () { return !!getToken(); },

        // 发送验证码
        requestCode: function (email) {
            return api('/api/auth/request-code', {
                method: 'POST',
                body: JSON.stringify({ email: email })
            });
        },

        // 校验验证码并登录（未注册自动建号），成功自动保存 token
        verifyCode: async function (email, code) {
            var data = await api('/api/auth/verify-code', {
                method: 'POST',
                body: JSON.stringify({ email: email, code: code })
            });
            setToken(data.token);
            return data;
        },

        // 6 位数字密码登录
        loginPassword: async function (email, password) {
            var data = await api('/api/auth/login-password', {
                method: 'POST',
                body: JSON.stringify({ email: email, password: password })
            });
            setToken(data.token);
            return data;
        },

        // 设置/修改 6 位数字密码（需已登录）
        setPassword: function (password) {
            return api('/api/auth/set-password', {
                method: 'POST',
                body: JSON.stringify({ password: password })
            });
        },

        // 校验当前会话
        me: function () {
            return api('/api/auth/me');
        },

        // 退出登录（仅清除本地 token；如需服务端注销可另加接口）
        logout: function () {
            setToken(null);
        }
    };

    global.AccountAuth = AccountAuth;
    if (typeof module !== 'undefined' && module.exports) module.exports = AccountAuth;
})(typeof window !== 'undefined' ? window : this);
