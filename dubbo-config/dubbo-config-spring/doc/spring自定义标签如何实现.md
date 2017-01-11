##  一.完成一个自定义配置一般需要以下步骤
1. 设计配置属性和JavaBean
2. 编写XSD文件
3. 编写NamespaceHandler和BeanDefinitionParser完成解析工作
4. 编写spring.handlers和spring.schemas串联起所有部件
5. 在Bean文件中应用

 ## 二.设计配置属性和JavaBean
 
需要配置User实体，配置属性name和age,id是默认需要的

```
public class User {  
    private String id;  
    private String name;  
    private int age;  
}  
```
## 三.编写XSD文件
JavaBean编写XSD文件，XSD是schema的定义文件

```
<?xml version="1.0" encoding="UTF-8"?>  
<xsd:schema   
    xmlns="http://blog.csdn.NET/cutesource/schema/people"  
    xmlns:xsd="http://www.w3.org/2001/XMLSchema"   
    xmlns:beans="http://www.springframework.org/schema/beans"  
    targetNamespace="http://blog.csdn.Net/cutesource/schema/people"  
    elementFormDefault="qualified"   
    attributeFormDefault="unqualified">  
    <xsd:import namespace="http://www.springframework.org/schema/beans" />  
    <xsd:element name="user">  
        <xsd:complexType>  
            <xsd:complexContent>  
                <xsd:extension base="beans:identifiedType">  
                    <xsd:attribute name="name" type="xsd:string" />  
                    <xsd:attribute name="age" type="xsd:int" />  
                </xsd:extension>  
            </xsd:complexContent>  
        </xsd:complexType>  
    </xsd:element>  
</xsd:schema> 
```

xsd:schema详细内容可参考：
[http://www.w3school.com.cn/schema/schema_schema.asp](http://www.w3school.com.cn/schema/schema_schema.asp)


```
<xsd:element name="user">
```
对应着配置项节点的名称，因此在应用中会用user作为节点名来引用这个配置

```
<xsd:attribute name="name" type="xsd:string" />
<xsd:attribute name="age" type="xsd:int" />
```
user的两个属性名,分别是string和int类型

把xsd存放在classpath下，一般都放在META-INF目录下

## 四.编写NamespaceHandler和BeanDefinitionParser完成解析工作
解析工作用到NamespaceHandler和BeanDefinitionParser这两个概念。
NamespaceHandler会根据schema和节点名找到BeanDefinitionParser，然后由BeanDefinitionParser完成具体的解析工作。Spring提供了默认实现类NamespaceHandlerSupport和AbstractSingleBeanDefinitionParser。简单的方式就是去继承这两个类。

```
import org.springframework.beans.factory.xml.NamespaceHandlerSupport;  
public class NamespaceHandler extends NamespaceHandlerSupport {  
    public void init() {  
        //节点名和解析类联系起来
        registerBeanDefinitionParser("user", new UserBeanDefinitionParser());  
    }  
}  
```

```
import org.springframework.beans.factory.support.BeanDefinitionBuilder;  
import org.springframework.beans.factory.xml.AbstractSingleBeanDefinitionParser;  
import org.springframework.util.StringUtils;  
import org.w3c.dom.Element;  
public class UserBeanDefinitionParser extends AbstractSingleBeanDefinitionParser {  
    protected Class getBeanClass(Element element) {  
        return User.class;  
    }  
    protected void doParse(Element element, BeanDefinitionBuilder bean) {  
        //element.getAttribute：用配置中取得属性值
        String name = element.getAttribute("name");  
        String age = element.getAttribute("age");  
        String id = element.getAttribute("id");  
        if (StringUtils.hasText(id)) {
            //bean.addPropertyValue:把属性值放到bean中
            bean.addPropertyValue("id", id);  
        }  
        if (StringUtils.hasText(name)) {  
            bean.addPropertyValue("name", name);  
        }  
        if (StringUtils.hasText(age)) {  
            bean.addPropertyValue("age", Integer.valueOf(age));  
        }  
    }  
} 
```
## 五.编写spring.handlers和spring.schemas
spring提供了spring.handlers和spring.schemas配置文件来把handler与xsd引入到工作体系中。spring.handlers和spring.schemas放入META-INF文件夹中，地址必须是META-INF/spring.handlers和META-INF/spring.schemas，spring会默认去载入它们。
spring.handlers如下所示：

```
http/://www.ziweigong.com/schema/user=NamespaceHandler
```
使用到名为"http://www.ziweigong.com/schema/user"的schema引用时，会通过NamespaceHandler来完成解析
spring.schemas如下所示：

```
http/://www.ziweigong.com/schema/user.xsd=META-INF/user.xsd
```
载入xsd文件



## 六.在Bean文件中应用

引用方式如下所示：

```
<?xml version="1.0" encoding="UTF-8"?>  
<beans xmlns="http://www.springframework.org/schema/beans"  
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"   
    xmlns:demo="http/://www.ziweigong.com/schema/user"  
    xsi:schemaLocation="  
http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans-2.5.xsd  
http/://www.ziweigong.com/schema/user http/://www.ziweigong.com/schema/user.xsd">  
    <demo:user id="liujia" name="刘佳" age="18"/>  
</beans>  
```
xmlns:demo="http/://www.ziweigong.com/schema/user是用来指定自定义schema
xsi:schemaLocation用来指定xsd文件
<demo:user id="liujia" name="刘佳" age="18"/>  是一个具体的自定义配置使用实例。

## 七.测试


```
ApplicationContext ctx = new ClassPathXmlApplicationContext("application.xml");  
User user = (User)ctx.getBean("liujia");  
System.out.println(user.getId());  
System.out.println(user.getName());  
System.out.println(user.getAge());  
```
输出：  
liujia  
刘佳  
18  