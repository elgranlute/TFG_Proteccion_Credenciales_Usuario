/*Metodos para obtener el par de claves de AndroidKeyStore*/
    public void loadKeyStore() {
        try {
            keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
            keyStore.load(null);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /*Metodo para generar el par de claves publica-privada*/
    public void generateNewKeyPair(String alias, Context context) throws Exception {
        Calendar start = Calendar.getInstance();
        Calendar end = Calendar.getInstance();
        // expires 1 year from today
        end.add(Calendar.YEAR, 1);
        KeyPairGeneratorSpec spec = new KeyPairGeneratorSpec.Builder(context)
                .setAlias(alias)
                .setSubject(new X500Principal("CN=" + alias))
                .setSerialNumber(BigInteger.TEN)
                .setStartDate(start.getTime())
                .setEndDate(end.getTime())
                .build();
        // use the Android keystore
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA",ANDROID_KEYSTORE);
        gen.initialize(spec);
        // generates the keypair
        gen.generateKeyPair();
    }

    /*Obtener clave publica*/
    public PublicKey loadPublicKey(String alias) throws Exception {
        KeyStore.Entry entry = keyStore.getEntry(alias, null);
        if (!(entry instanceof KeyStore.PrivateKeyEntry)) {
            Log.d("KeyStore", " alias: " + alias + " is not a PrivateKey");
            return null;
        }
        PublicKey publicKey = (PublicKey) ((KeyStore.PrivateKeyEntry)entry).getCertificate().getPublicKey();
        return publicKey;
    }

    /*Obtener clave privada*/
    public PrivateKey loadPrivateKey(String alias) throws Exception {
        KeyStore.Entry entry = keyStore.getEntry(alias, null);
        if (!(entry instanceof KeyStore.PrivateKeyEntry)) {
            Log.d("KeyStore", " alias: " + alias + " is not a PrivateKey");
            return null;
        }
        PrivateKey privateKey = (PrivateKey) ((KeyStore.PrivateKeyEntry)entry).getPrivateKey();
        return privateKey;
    }

    /*Obtener cifrador de RSA*/
    public Cipher getCipherRSA() throws NoSuchPaddingException, NoSuchAlgorithmException {
        return Cipher.getInstance("RSA/NONE/PKCS1Padding");
    }

    /*Cifrado con RSA*/
    public String cifradoRSA(String alias, String texto){
        Log.d("Cifrado","cifradoRSA");
        Cipher cifrador;
        String res = null;
        try {
            cifrador = getCipherRSA();
            //Obtener la clave publica para cifrar
            PublicKey publicKey = loadPublicKey(alias);
            cifrador.init(Cipher.ENCRYPT_MODE, publicKey);
            res = Base64.encodeToString(cifrador.doFinal(texto.getBytes()), Base64.NO_WRAP);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return res;
    }

    /*Descifrado con RSA*/
    public String descifradoRSA(String alias, String textoCifrado){
        Log.d("Cifrado","descifradoRSA");
        Cipher cifrador;
        try {
            cifrador = getCipherRSA();
            //Obtener la clave privada para descifrar
            PrivateKey privateKey = loadPrivateKey(alias);
            if(privateKey == null){
                Log.d("KeyStore","no hay privateKey");
            }
            cifrador.init(Cipher.DECRYPT_MODE, privateKey);
            return new String (cifrador.doFinal(Base64.decode(textoCifrado, Base64.NO_WRAP)));
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /*Obtener cifrador de AES*/
    public Cipher getCipherAES() throws NoSuchPaddingException, NoSuchAlgorithmException {
        return Cipher.getInstance("AES_256/ECB/PKCS5Padding");
    }

    /*Generar clave secreta AES-256*/
    public SecretKey generarClaveSecreta() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        SecretKey secretKey = keyGenerator.generateKey();
        return secretKey;
    }

    /*Cifrado simetrico AES-256*/
    public String cifradoSimetrico(SecretKey secretKey, String textoPlano){
        Log.d("Cifrado","cifrado SIMETRICO");
        Cipher cifrador;
        String res = null;
        try {
            cifrador = getCipherAES();
            cifrador.init(Cipher.ENCRYPT_MODE, secretKey);
            res = Base64.encodeToString(cifrador.doFinal(textoPlano.getBytes()), Base64.NO_WRAP);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return res;
    }

    /*Descifrado simetrico AES-256*/
    public String descifradoSimetrico(SecretKey secretKey, String textoCifrado){
        Log.d("Cifrado","descifrado SIMETRICO");
        Cipher cifrador;
        try {
            cifrador = getCipherAES();
            cifrador.init(Cipher.DECRYPT_MODE, secretKey);
            return new String (cifrador.doFinal(Base64.decode(textoCifrado, Base64.NO_WRAP)));
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }