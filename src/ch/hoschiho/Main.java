package ch.hoschiho;

import java.util.HashMap;

public class Main {

    public static void main(String[] args) {

        String chiffreText =
            "00000100110100100000101110111000000000101000111110001110011111110110000001010001010000111010000000010011011001110010101110110000";

        ////////////Initialize SPN with given parameters////////////

        int r = 4;
        int n = 4;
        int m = 4;
        int s = 32;
        int l = n * m;

        HashMap<String, String> sBox = new HashMap<String, String>();
        fillSBox(sBox);

        HashMap<String, String> inverseSBox = new HashMap<String, String>();
        fillInverseSBox(inverseSBox);

        HashMap<Integer, Integer> pBox = new HashMap<Integer, Integer>();
        fillPBox(pBox);

        String key = "00111010100101001101011000111111";

        //TestStrings ot test the SPN
        String testK = "00010001001010001000110000000000";
        String testX = "0001001010001111";
        String testY = "1010111010110100";

        System.out.println("test encryption: " + encrypt(testX,testK,r,sBox,pBox));
        System.out.println("test decryption: " + decrypt(testY,testK,r,inverseSBox,pBox));


        ////////////CTR Encryption////////////

        String randY = chiffreText.substring(0, n * m); //get y-1 from chiffretext

        StringBuilder SBdecryptedInASCII = new StringBuilder();


        for (int i = 0; (i + 1) * l < chiffreText.length(); i++) {

            //Calculate y-1 + 1 mod 2^l and format it to the correct binary string
            String Y_i =
                String.format("%16s", Integer.toBinaryString((int) ((Integer.parseInt(randY, 2) + i) % Math.pow(2, l))))
                    .replace(' ', '0');

            String block = chiffreText.substring((i + 1) * l, (i + 1) * l + l); // get the current block

            String encryptedY_i = encrypt(Y_i, key, r, sBox, pBox); //encrypt Y_i with the SPN

            String result = xor(encryptedY_i, block); //xor the encrypted Y_i with the block

            SBdecryptedInASCII.append(result); //create a string
        }

        String decryptedInASCIInoFill = removeFillBits(SBdecryptedInASCII.toString()); //get rid of the last '1000...'

        String decryptedMessage = convertASCII(decryptedInASCIInoFill); //convert text to it to ASCII
        System.out.println("decrypted Message: " + decryptedMessage);
    }


    ////////////SPN Encryption////////////

    private static String encrypt(String x, String key, int r, HashMap<String, String> sBox,
                                  HashMap<Integer, Integer> pBox) {

        // 1. initial white step
        x = xor(x, calcRoundKey(key, 0));

        // 2. Rounds
        for (int i = 1; i < r; i++) {

            //WordSubstitution
            x = wordSubstitution(x, sBox);

            //BitPermutation
            x = bitPermutation(x, pBox);

            //RoundKeyAddition
            x = xor(x, calcRoundKey(key, i));
        }

        // 3. shortened round (without BitPermutation)
        x = wordSubstitution(x, sBox);

        x = xor(x, calcRoundKey(key, r));

        return x;
    }


    ////////////SPN Decrpytion////////////

    private static String decrypt(String x, String key, int r, HashMap<String, String> InverseSBox,
                                  HashMap<Integer, Integer> pBox) {

        // 1. initial white step
        x = xor(x, calcRoundKey(key, r));

        // 2. Rounds
        for (int i = 1; i < r; i++) {

            //WordSubstitution
            x = wordSubstitution(x, InverseSBox);

            //BitPermutation
            x = bitPermutation(x, pBox);

            //RoundKeyAddition
            x = xor(x, bitPermutation(calcRoundKey(key, r - i), pBox));
        }

        // 3. shortened round (without BitPermutation)
        x = wordSubstitution(x, InverseSBox);

        x = xor(x, calcRoundKey(key, 0));

        return x;

    }

    ////////////Helper functions SPN////////////

    private static String bitPermutation(String x, HashMap<Integer, Integer> pBox) {
        StringBuilder permutatedX = new StringBuilder(x);

        for (int i = 0; i < x.length(); i++) {
            permutatedX.setCharAt(pBox.get(i), x.charAt(i));
        }
        return permutatedX.toString();
    }

    private static String xor(String x, String k) {
        StringBuilder result = new StringBuilder();

        for (int i = 0; i < k.length(); i++) {
            if (x.charAt(i) == k.charAt(i)) {
                result.append("0");
            } else {
                result.append("1");
            }
        }
        return result.toString();
    }

    private static String wordSubstitution(String x, HashMap<String, String> sBox) {

        StringBuilder substitutedX = new StringBuilder();

        for (int i = 0; i < x.length(); i += 4) {
            String word = x.substring(i, i + 4);
            substitutedX.append(sBox.get(word));
        }

        return substitutedX.toString();
    }

    private static String calcRoundKey(String k, int round) {
        return k.substring(round * 4, round * 4 + 16);
    }


    //////////// General helper functions////////////

    private static String convertASCII(String decryptedInASCIInoFill) {
        StringBuilder converted = new StringBuilder();

        for (int i = 0; i < decryptedInASCIInoFill.length() / 8; i++) {

            int a = Integer.parseInt(decryptedInASCIInoFill.substring(8 * i, (i + 1) * 8), 2);
            converted.append((char) (a));
        }
        return (converted.toString());
    }

    private static String removeFillBits(String decryptedInASCII) {
        int cutPoint = 0;
        for (int i = decryptedInASCII.length() - 1; i > 0; i--) {

            if (decryptedInASCII.charAt(i) == '1') {
                cutPoint = i;
                break;
            }
        }
        return decryptedInASCII.substring(0, cutPoint);
    }


    //////////// Fill HashMaps////////////

    private static HashMap<String, String> fillSBox(HashMap<String, String> sBox) {
        sBox.put("0000", "1110");
        sBox.put("0001", "0100");
        sBox.put("0010", "1101");
        sBox.put("0011", "0001");
        sBox.put("0100", "0010");
        sBox.put("0101", "1111");
        sBox.put("0110", "1011");
        sBox.put("0111", "1000");
        sBox.put("1000", "0011");
        sBox.put("1001", "1010");
        sBox.put("1010", "0110");
        sBox.put("1011", "1100");
        sBox.put("1100", "0101");
        sBox.put("1101", "1001");
        sBox.put("1110", "0000");
        sBox.put("1111", "0111");

        return sBox;
    }

    private static HashMap<String, String> fillInverseSBox(HashMap<String, String> inverseSBox) {
        inverseSBox.put("1110", "0000");
        inverseSBox.put("0100", "0001");
        inverseSBox.put("1101", "0010");
        inverseSBox.put("0001", "0011");
        inverseSBox.put("0010", "0100");
        inverseSBox.put("1111", "0101");
        inverseSBox.put("1011", "0110");
        inverseSBox.put("1000", "0111");
        inverseSBox.put("0011", "1000");
        inverseSBox.put("1010", "1001");
        inverseSBox.put("0110", "1010");
        inverseSBox.put("1100", "1011");
        inverseSBox.put("0101", "1100");
        inverseSBox.put("1001", "1101");
        inverseSBox.put("0000", "1110");
        inverseSBox.put("0111", "1111");

        return inverseSBox;
    }

    private static HashMap<Integer, Integer> fillPBox(HashMap<Integer, Integer> bitPermutation) {
        bitPermutation.put(0, 0);
        bitPermutation.put(1, 4);
        bitPermutation.put(2, 8);
        bitPermutation.put(3, 12);
        bitPermutation.put(4, 1);
        bitPermutation.put(5, 5);
        bitPermutation.put(6, 9);
        bitPermutation.put(7, 13);
        bitPermutation.put(8, 2);
        bitPermutation.put(9, 6);
        bitPermutation.put(10, 10);
        bitPermutation.put(11, 14);
        bitPermutation.put(12, 3);
        bitPermutation.put(13, 7);
        bitPermutation.put(14, 11);
        bitPermutation.put(15, 15);

        return bitPermutation;
    }

}
