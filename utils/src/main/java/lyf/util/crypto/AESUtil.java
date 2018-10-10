package lyf.util.crypto;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * @author lyf
 * @date 2018-10-10 16:06:36
 * @descripe AES对称加密、解密
 */
public class AESUtil {

    /**
     * 加密
     * @param secret 秘钥
     * @param content 待加密数据
     * @return 加密后的数据字符串
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws UnsupportedEncodingException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    public static String AESEncode(String secret, String content) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, UnsupportedEncodingException, BadPaddingException, IllegalBlockSizeException {
        // 1.构造秘钥生成器，AES不区分大小写
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");

        // 2. 使用SHA1PRNG规则加密
        SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
        // 根据秘钥生成随机数
        secureRandom.setSeed(secret.getBytes());
        // 生成一个128位的随机源
        keyGenerator.init(128,secureRandom);
        // 3.产生随机秘钥
        SecretKey secretKey = keyGenerator.generateKey();
        // 4.获取原始对称秘钥的字节数组
        byte[] raw = secretKey.getEncoded();
        // 5.根据字节数组生成AES秘钥
        SecretKey key = new SecretKeySpec(raw, "AES");
        // 6.根据字节数组生成AES自成密码器
        Cipher cipher = Cipher.getInstance("AES");
        // 7.初始化密码器，第一个参数为加密(Encrypt_mode)操作，第二个参数为使用的KEY
        cipher.init(Cipher.ENCRYPT_MODE, key);
        // 8.获取加密内容的字节数组(这里要设置为utf-8)不然内容中如果有中文和英文混合中文就会解密为乱码
        byte[] byte_encode = content.getBytes("utf-8");
        // 9.加密数据
        byte[] byte_AES = cipher.doFinal(byte_encode);
        // 10.将加密后的数据转换为字符串
        // 如果这里用Base64Encoder中提示找不到包
        // 解决办法：
        // 在项目的Build path中先移除JRE System Library，再添加库JRE System Library，重新编译后就一切正常了。
        String AES_encode = new String(new BASE64Encoder().encode(byte_AES));
        // 返回字符串
        return AES_encode;
    }

    /**
     * 解密
     * @param secret 秘钥
     * @param content 加密后的数据
     * @return
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws IOException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    public static String AESDncode(String secret, String content) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IOException, BadPaddingException, IllegalBlockSizeException {

        // 1. 构造秘钥生成器
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        // 2. 初始化秘钥生成器
        SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
        secureRandom.setSeed(secret.getBytes());
        keyGenerator.init(128,secureRandom);
        // 3.产生原始对称秘钥
        SecretKey secretKey = keyGenerator.generateKey();
        // 4.获得原始对称秘钥的字节数组
        byte[] raw = secretKey.getEncoded();
        // 5.根据字节数组生成AES密钥
        SecretKey key=new SecretKeySpec(raw, "AES");
        // 6.根据指定算法AES自成密码器
        Cipher cipher=Cipher.getInstance("AES");
        // 7.初始化密码器，第一个参数为解密(Decrypt_mode)操作，第二个参数为使用的KEY
        cipher.init(Cipher.DECRYPT_MODE, key);
        // 8.将解密并编码后的内容解码成字节数组
        byte [] byte_content= new BASE64Decoder().decodeBuffer(content);
        // 9.解密
        byte [] byte_decode=cipher.doFinal(byte_content);
        String AES_decode=new String(byte_decode,"utf-8");
        return AES_decode;
    }

    /**
     * test
     * @param args
     */
    public static void main(String[] args) {
        try {
            String en = AESEncode("lyf","123456");
            String de = AESDncode("lyf",en);
            System.out.println(en+"\n"+de);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
