package com.itheima.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.itheima.config.RsaKeyProperties;
import com.itheima.domain.Payload;
import com.itheima.domain.SysUser;
import com.itheima.utils.JwtUtils;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.Map;

/**
 * 原生BasicAuthenticationFilter过滤器中doFilterInternal方法校验用户是否登录，就是看session中是否有用户信息，
 * 我们要修改为，验证用户携带的token是否合法，并解析出用户信息，交给SpringSecurity，以便于后续的授权功能可以正常使用
 */
public class JwtVerifyFilter extends BasicAuthenticationFilter {

    private RsaKeyProperties prop;

    public JwtVerifyFilter(AuthenticationManager authenticationManager, RsaKeyProperties prop) {
        super(authenticationManager);
        this.prop = prop;
    }

    public void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        String header = request.getHeader("Authorization");
        if (header == null || !header.startsWith("Bearer ")) {
            //如果携带错误的token，则给用户提示请登录！
//            chain.doFilter(request, response);
            responseJson(response);
            return;
        }
        //获取权限失败，会抛出异常
        UsernamePasswordAuthenticationToken authentication = getAuthentication(request);
        //获取后，将Authentication写入SecurityContextHolder中供后续使用
        SecurityContextHolder.getContext().setAuthentication(authentication);
        chain.doFilter(request, response);
    }

    /*** 未登录提示 * @param response */
    private void responseJson(HttpServletResponse response) {
        try {
            //未登录提示
            response.setContentType("application/json;charset=utf-8");
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            PrintWriter out = response.getWriter();
            Map<String, Object> map = new HashMap<>();
            map.put("code", HttpServletResponse.SC_FORBIDDEN);
            map.put("message", "请登录！");
            out.write(new ObjectMapper().writeValueAsString(map));
            out.flush();
            out.close();
        } catch (Exception e1) {
            e1.printStackTrace();
        }
    }

    /*** 通过token，获取用户信息 ** @param request * @return */
    private UsernamePasswordAuthenticationToken getAuthentication(HttpServletRequest request) {
        String token = request.getHeader("Authorization");
        if (token != null) { //通过token解析出载荷信息
            Payload<SysUser> payload = JwtUtils.getInfoFromToken(token.replace("Bearer ", ""), prop.getPublicKey(), SysUser.class);
            SysUser user = payload.getUserInfo(); //不为null，返回
            if (user != null) {
                return new UsernamePasswordAuthenticationToken(user, null, user.getRoles());
            }
            return null;
        }
        return null;
    }

}
