package com.study.controller;

import com.study.model.User;
import com.study.util.PasswordHelper;
import net.sf.json.JSONObject;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.*;
import org.apache.shiro.subject.Subject;

import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.HashMap;
import java.util.Map;

/**
 * Created by yangqj on 2017/4/21.
 */
@RestController
public class HomeController {

    @RequestMapping(value = "/login", method = RequestMethod.POST)
    public String login(@RequestBody User userInfo) {
        JSONObject jsonObject = new JSONObject();
        Subject subject = SecurityUtils.getSubject();
        UsernamePasswordToken token = new UsernamePasswordToken(userInfo.getUsername(), userInfo.getPassword());
        try {
            subject.login(token);
            jsonObject.put("token", subject.getSession().getId());
            jsonObject.put("msg", "登录成功");
        } catch (IncorrectCredentialsException e) {
            token.clear();
            jsonObject.put("msg", "密码错误");
        } catch (LockedAccountException e) {
            token.clear();
            jsonObject.put("msg", "登录失败，该用户已被冻结");
        } catch (AuthenticationException e) {
            token.clear();
            jsonObject.put("msg", "该用户不存在");
        } catch (Exception e) {
            e.printStackTrace();
        }
        return jsonObject.toString();
    }

    @PostMapping("/logout")
    public Map logout(HttpServletResponse response, HttpServletRequest request){
        System.err.println(request.getHeader("Origin"));
        response.setHeader("Access-Control-Allow-Origin", request.getHeader("Origin"));
        response.setHeader("Access-Control-Allow-Credentials", "true");
        Map<String, Object> map = new HashMap<>();
        Subject subject = SecurityUtils.getSubject();
        subject.logout();
        map.put("msg", "logout success");
        return map;
    }

    /**
     * 未登录，shiro应重定向到登录界面，此处返回未登录状态信息由前端控制跳转页面
     * @return
     */
    @RequestMapping(value = "/unauth")
    public Object unauth() {
        Map<String, Object> map = new HashMap<>();
        map.put("code", "1000000");
        map.put("msg", "未登录");
        return map;
    }

    @GetMapping("/getall")
    public Map getall(HttpServletResponse response, HttpServletRequest request) {
        System.err.println(request.getHeader("Origin"));
        response.setHeader("Access-Control-Allow-Origin", request.getHeader("Origin"));
        response.setHeader("Access-Control-Allow-Credentials", "true");
        Map<String, Object> map = new HashMap<>();
        map.put("msg","test");
        return map;
    }

//    @PostMapping("/add")
//    public String add(@RequestBody User user) {
//        User u = userService.selectByUsername(user.getUsername());
//        if(u != null) {
//            return "error";
//        }
//        try {
//            user.setEnable(1);
//            PasswordHelper passwordHelper = new PasswordHelper();
//            passwordHelper.encryptPassword(user);
//            userService.addUser(user);
//            return "success";
//        } catch (Exception e) {
//            e.printStackTrace();
//            return "fail";
//        }
//    }
//    @RequestMapping(value="/login",method= RequestMethod.GET)
//    public String login(){
//        return "login";
//    }
//
//    @RequestMapping(value="/login",method=RequestMethod.POST)
//    public String login(HttpServletRequest request, User user, Model model){
//        if (StringUtils.isEmpty(user.getUsername()) || StringUtils.isEmpty(user.getPassword())) {
//            request.setAttribute("msg", "用户名或密码不能为空！");
//            return "login";
//        }
//        Subject subject = SecurityUtils.getSubject();
//        UsernamePasswordToken token=new UsernamePasswordToken(user.getUsername(),user.getPassword());
//        try {
//            subject.login(token);
//            return "redirect:usersPage";
//        }catch (LockedAccountException lae) {
//            token.clear();
//            request.setAttribute("msg", "用户已经被锁定不能登录，请与管理员联系！");
//            return "login";
//        } catch (AuthenticationException e) {
//            token.clear();
//            request.setAttribute("msg", "用户或密码不正确！");
//            return "login";
//        }
//    }
//    @RequestMapping(value={"/usersPage",""})
//    public String usersPage(){
//        return "user/users";
//    }
//
//    @RequestMapping("/rolesPage")
//    public String rolesPage(){
//        return "role/roles";
//    }
//
//    @RequestMapping("/resourcesPage")
//    public String resourcesPage(){
//        return "resources/resources";
//    }
//
//    @RequestMapping("/403")
//    public String forbidden(){
//        return "403";
//    }
}
