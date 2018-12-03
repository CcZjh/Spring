package com.jwt.utils;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.BeanUtils;  
  
/** 
 * requst流对象工具类 
 * @author LUSHUIFA242 
 * 
 */  
public class RequestStreamUtil {  
      
    /** 
     * 将request流中的数据转换成String 
     * @param request 
     * @return 
     */  
      public static String toString(HttpServletRequest request){  
            String valueStr = "";  
            try {  
                StringBuffer sb = new StringBuffer();  
                InputStream is = request.getInputStream();  
                InputStreamReader isr = new InputStreamReader(is);  
                BufferedReader br = new BufferedReader(isr);  
                String s = "";  
                while ((s = br.readLine()) != null) {  
                    sb.append(s);  
                }  
                valueStr = sb.toString();  
            } catch (IOException e) {  
                e.printStackTrace();  
                valueStr = "";  
            }  
            return valueStr;  
      }  
        
       /** 
         * 将request流中的数据转换成Map 
         * @param request 
         * @return 
         */  
        public static Map<String,String> toMap(HttpServletRequest request){  
            Map<String,String> parameter = new HashMap<String,String>();  
            String valueStr = toString(request);  
            try {  
                if(null!=valueStr&&!"".equals(valueStr)){
                	valueStr = valueStr.replaceAll("\\{", "");
                	valueStr = valueStr.replaceAll("\\}", "");
                	valueStr = valueStr.replaceAll("\"","");
                    String[] valueArr = valueStr.split(",");  
                    for (String kvStr : valueArr) {  
                        String[] kvStrArr = kvStr.split(":");  
                        parameter.put(kvStrArr[0], kvStrArr[1]);  
                    }  
                }else{  
                    parameter = getParameterMap(request);  
                }  
            } catch (Exception e) {  
                e.printStackTrace();  
            }  
            return parameter;  
        }  
          
        /** 
         * 将request流中的数据转换成bean 
         * @param request 
         * @return 
         */  
        public static Object toBean(HttpServletRequest request,Class<?> beanClazz){  
            Map<String, String> mapObject = toMap(request);  
            System.out.println("toBean:"+mapObject);  
            Object beanO = null;  
            try {  
                beanO = beanClazz.newInstance();  
                if(null!=mapObject&&!mapObject.isEmpty()){  
                    BeanUtils.copyProperties(beanO,mapObject);  
                }  
            } catch (Exception e) {  
                e.printStackTrace();  
            }  
            return beanO;  
        }  
          
        /**  
         * 从request中获得参数Map，并返回可读的Map  
         * @param request  
         * @return  
         */  
        public static Map<String,String> getParameterMap(HttpServletRequest request) {    
            // 参数Map    
            Map properties = request.getParameterMap();    
            // 返回值Map    
            Map<String,String> returnMap = new HashMap<String,String>();    
            Iterator entries = properties.entrySet().iterator();    
            Map.Entry<String,String> entry;    
            String name = "";    
            String value = "";    
            while (entries.hasNext()) {    
                entry = (Map.Entry) entries.next();    
                name = (String) entry.getKey();    
                Object valueObj = entry.getValue();    
                if(null == valueObj){    
                    value = "";    
                }else if(valueObj instanceof String[]){    
                    String[] values = (String[])valueObj;    
                    for(int i=0;i<values.length;i++){    
                        value = values[i] + ",";    
                    }    
                    value = value.substring(0, value.length()-1);    
                }else{    
                    value = valueObj.toString();    
                }    
                returnMap.put(name, value);    
            }  
            return returnMap;    
        }  
}  