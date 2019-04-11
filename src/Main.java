import org.jetbrains.annotations.Contract;
import org.jetbrains.annotations.NotNull;

import java.io.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.nio.*;
import static java.lang.Math.*;

public class Main {

    private static final int w = 32;
    private static final int P32 = 0xB7E15163;
    private static final int Q32 = 0x9E3779B9;
    private static final int r = 20;
    private static final int modul = (int)pow(2,32);
    private static int k[] = new int[2*r + 4]; //{0x00000001,0x00000001,0x00000001,0x00000001,0x00000001,0x00000001,0x00000001,0x00000001,0x00000001,0x00000001,0x00000001,0x00000001,0x00000001,0x00000001,0x00000001,0x00000001,0x00000001,0x00000001,0x00000001,0x00000001,0x00000001,0x00000001,0x00000001,0x00000001,0x00000001,0x00000001,0x00000001,0x00000001,0x00000001,0x00000001,0x00000001,0x00000001,0x00000001,0x00000001,0x00000001,0x00000001,0x00000001,0x00000001,0x00000001,0x00000001,0x00000001,0x00000001,0x00000001,0x00000001};

    @Contract(pure = true)
    private static int T(int x){
        return (x*(2*x+1)) % (int)pow(2,32);
    }

    @Contract(pure = true)
    private static int ROTL(int x, int y) { return Integer.rotateLeft(x, y);
//         return ((((x)<<(y&(32-1)))) | ((x)>>(w-(y&(32-1)))))
     }

    @Contract(pure = true)
    private static int ROTR(int x, int y) { return Integer.rotateRight(x, y);
//        return (((x)>>(y&(w-1))) | ((x)<<(w-(y&(w-1)))))
    }

    @NotNull
    private static byte[] byteArrayFromArrayListOfByteArray(@NotNull ArrayList<byte[]> newMass) {
        byte byteArray[] = new byte[newMass.size()*newMass.get(0).length];
        int ind = 0;
        for (byte[] g: newMass) {
            for (byte f: g) {
                byteArray[ind] = f;
                ind++;
            }
        }
        return byteArray;
    }

    private static int[] byteArrayToInt(byte[] ABCD) {
        int[] ABCDInt = new int[4];
        for (int i = 0, ind = 0; i < 4; i++, ind+=4){
            ABCDInt[i] = ByteBuffer.wrap(Arrays.copyOfRange(ABCD,ind,ind+4)).getInt();
        }
        return ABCDInt;
    }

    @NotNull
    private static byte[] IntToByteArray(int a, int b, int c, int d) {
        int[] temp1 = new int[]{a,b,c,d};
        ArrayList<byte[]> temp2 = new ArrayList<>();
        for (int i = 0, ind = 0; i < 4; i++, ind+=4){
            temp2.add(ByteBuffer.allocate(4).putInt(temp1[i]).array());
        }
        return byteArrayFromArrayListOfByteArray(temp2);
    }

/** ОСНОВНАЯ ФУНКЦИЯ */
    public static void main(String[] args) throws Exception {
//ЧТЕНИЕ СООБЩЕНИЯ
        File inFile = new File("src/forEncrypt.txt");
        InputStream fIn = new FileInputStream(inFile);

        ArrayList<byte[]> massOfMessBlocks = new ArrayList<>();
        while (fIn.available() != 0) {
                massOfMessBlocks.add(fIn.readNBytes(16));
        }
        fIn.close();
        massOfMessBlocks.set(massOfMessBlocks.size()-1,Arrays.copyOf(massOfMessBlocks.get(massOfMessBlocks.size()-1), 16));

        byte originalMessBytes[] = byteArrayFromArrayListOfByteArray(massOfMessBlocks);
        String originalMess = new String(originalMessBytes);
        System.out.println("Исходное сообщение: " + originalMess + " || " + Arrays.toString(massOfMessBlocks.get(0)));

//ФОРМИРОВАНИЕ КЛЮЧА
        String key = "hnsbjvnlmblvijean;minmegnmjignmeirofmc,rwmvd";
        key_setup(key);

//ШИФРОВАНИЕ
        ArrayList<byte[]> massOfEncryptBlocks = encrypt(massOfMessBlocks);

//ОБРАБОТКА РЕЗУЛЬТАТА ШИФРОВАНИЯ
        byte encryptMessBytes[] = byteArrayFromArrayListOfByteArray(massOfEncryptBlocks);
        String encryptMess = new String(encryptMessBytes);
        System.out.println("Зашифрованное сообщение: " + encryptMess + " || " + Arrays.toString(encryptMessBytes));

//ЗАПИСЬ ШИФРА В ФАЙЛ
        File outFile = new File("src/forDecrypt.txt");
        FileOutputStream fOut = new FileOutputStream(outFile);
        fOut.write(encryptMessBytes);
        fOut.close();


//ЧТЕНИЕ ЗАШИФПРВАННОГО СООБЩЕНИЯ
        inFile = new File("src/forDecrypt.txt");
        fIn = new FileInputStream(inFile);

        ArrayList<byte[]> massOfDecryptMessBlocks = new ArrayList<>();
        while (fIn.available() != 0) {
            massOfDecryptMessBlocks.add(fIn.readNBytes(16));
        }
        massOfDecryptMessBlocks.set(massOfDecryptMessBlocks.size()-1,Arrays.copyOf(massOfDecryptMessBlocks.get(massOfDecryptMessBlocks.size()-1), 16));

//РАСШИФРОКА
        ArrayList<byte[]> massDecryptBlocks = decrypt(massOfDecryptMessBlocks);

//ОБРАБОТКА РЕЗУЛЬТАТА РАСШИФРОВКИ
        byte[] decryptMessByte = byteArrayFromArrayListOfByteArray(massDecryptBlocks);
        String decryptMess = new String(decryptMessByte);
        System.out.println("Расшифрованное сообщение: " + decryptMess + " || " + Arrays.toString(decryptMessByte));

//ЗАПИСЬ РАСШИФРОВКИ В ФАЙЛ
        outFile = new File("src/decryptMess");
        fOut = new FileOutputStream(outFile);
        fOut.write(decryptMessByte);
        fOut.close();
    }

/** ФУНКЦИЯ ПОДГОТОВКИ КЛЮЧА */
    private static void key_setup(@NotNull String key) {

        byte[] keyB = Arrays.copyOf(key.getBytes(),((key.length()*8)%32 != 0)?(((key.length()*8)/32+1)*32):(key.length()));
        int c = keyB.length*8/32;

        int[] K = new int[c];
        int ind = 0;
        for (int i = 0; i < c; i++){
            K[i] = ByteBuffer.wrap(Arrays.copyOfRange(keyB,ind,ind+4)).getInt();
            ind +=4;
        }

        k[0] = P32;
        for (int i = 1 /*0*/;i<44;i++) {
            k[i] = k[i-1] + Q32;
        }

        int A = 0, B = 0,i = 0,j = 0;
        for (int x = 0; x < (44*3); x++){
            k[i] = ROTL(k[i] + A + B,3);
            A = k[i]; i = (i+1)%44;

            K[j] = ROTL((K[j]+A+B),(A+B));
            B = k[j]; j = (j + 1) % c;
        }
    }

/** ФУНКЦИЯ ШИФРОВАНИЯ */
    private static ArrayList<byte[]> encrypt(@NotNull ArrayList<byte[]> mass) {
        ArrayList<byte[]> massOfBlocks = new ArrayList<>();
        int x;
        int a,b,c,d;
        for (int i = 0; i < mass.size(); i++){
            int data[] = byteArrayToInt(mass.get(i));
            a = data[0]; b = data[1]; c = data[2]; d = data[3];

            b = ((b + k[0])%modul);
            d = ((d + k[1])%modul);
            for (int j = 1; j <= r; j++) {
                int t = ROTL(T(b), 5);
                int u = ROTL(T(d), 5);
                a = ((ROTL(a ^ t, u) + k[2*j])%modul);
                c = ((ROTL(c ^ u, t) + k[2*j+1])%modul);
                x = a;
                a = b;
                b = c;
                c = d;
                d = x;
            }
            a = ((a + k[2*r+2])%modul);
            c = ((c + k[2*r+3])%modul);

            massOfBlocks.add(IntToByteArray(a,b,c,d));
        }
        return massOfBlocks;
    }

/** ФУНКЦИЯ ДЕШИФРОВАНИЯ */
    private static ArrayList<byte[]> decrypt(@NotNull ArrayList<byte[]> mass){
        ArrayList<byte[]> massOfBlocks = new ArrayList<>();
        int x;
        int a,b,c,d;
        for (int i = 0; i < mass.size(); i++){

            int data[] = byteArrayToInt(mass.get(i));
            a = data[0]; b = data[1]; c = data[2]; d = data[3];

            c = ((c - k[2*r+3])%modul);
            a = ((a - k[2*r+2])%modul);
            for (int j = r; j >= 1; j --) {
                x = d;
                d = c;
                c = b;
                b = a;
                a = x;
                int u = ROTL(T(d), 5);
                int t = ROTL(T(b), 5);
                c = (ROTR(((c - k[2*j+1])%modul), t) ^ u);
                a = (ROTR(((a - k[2*j])%modul), u) ^ t);
            }
            d = ((d - k[1])%modul);
            b = ((b - k[0])%modul);

            massOfBlocks.add(IntToByteArray(a,b,c,d));
        }
        return massOfBlocks;
    }
}