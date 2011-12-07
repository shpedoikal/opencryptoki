
/*
 * opencryptoki_java_test.java
 *
 * This testcase generates 2 keys, one through the PKCS11 provider and one through the JCE. It
 * then creates a signature over arbitrary data using the JCE and verifies using PKCS11 and
 * vice versa. This will test whether openCryptoki is generating signatures correctly.
 *
 * It can test the following mechanisms:
 * CKM_SHA256_RSA_PKCS
 * CKM_SHA1_RSA_PKCS
 * CKM_MD5_RSA_PKCS
 *
 * It will test the following RSA key sizes:
 * 512
 * 1024
 * 2048
 * 4096
 *
 * Note that this test doesn't work on secure-key tokens. When the verify step is executed,
 * opencryptoki will fail to find the key object's CKA_IBM_OPAQUE attribute, since the public
 * key is generated through the JCE for half of these tests. This bug has been opened to fix
 * this issue: http://sf.net/tracker/?func=detail&aid=3439616&group_id=128009&atid=710344
 *
 * Kent Yoder <yoder1@us.ibm.com>
 */

import java.io.*;
import java.security.*;

import java.security.spec.*;
import java.security.interfaces.*;
import javax.crypto.*;
import com.ibm.crypto.pkcs11impl.provider.IBMPKCS11Impl;

import java.util.Iterator;


public class opencryptoki_java_test
{
	com.ibm.crypto.pkcs11impl.provider.IBMPKCS11Impl ibm_pkcs11impl;

	Provider provider;
	Provider jceProvider;
	String providerNameString;
	String jceProviderNameString;

	opencryptoki_java_test(String conf)
	{
		initializeProvider(conf);
	}

	void  initializeProvider(String conf)
	{
		try
		{
			ibm_pkcs11impl = new com.ibm.crypto.pkcs11impl.provider.IBMPKCS11Impl(conf);
		}
		catch (Exception e)
		{
			System.out.println("Error creating provider object: " + e.getMessage());
			System.out.println("Make sure pkcsslotd is running and that pkcsconf -t " +
					   "shows that your token is available");
			System.exit(-1);
		}

		Security.insertProviderAt(ibm_pkcs11impl, 1);

		provider = Security.getProvider("IBMPKCS11Impl-Sample");
		jceProvider = Security.getProvider("IBMJCE");
		providerNameString = "IBMPKCS11Impl-Sample";
		jceProviderNameString = "IBMJCE";


		if (provider != null)
		{
			System.out.println("The provider object used by this test is: " +
					   provider.getName());
			System.out.println("Provider version number is: " + provider.getVersion());
			System.out.println("Provider info is: " + provider.getInfo());
			System.out.println("The provider was loaded successfully.");
		}
		else
		{
			System.out.println("The provider was not found.");
			System.out.println("The loading of the provider FAILED.");
			System.exit(-1);
		}

		String pswd = System.getenv("PKCS11_USER_PIN");
		if (pswd == null) {
			System.out.println("Please set the PKCS11_USER_PIN env var to the " +
					   "CKU_USER PIN");
			System.exit(-1);
		}
		char [] passwd = new char[pswd.length()];
		pswd.getChars(0,pswd.length(),passwd,0);
		NullPrompter np = new NullPrompter(null, passwd);
		try
		{
			ibm_pkcs11impl.login(null, np);
		}
		catch(Exception e)
		{
			System.out.println("Login to crypto adapter failed.  EXITING.");
			System.exit(-1);
		}
	}

	public static void sign_verify(String   hash,
			int      key_len,
			byte[]   data_to_sign,
			String   provider)
	{
		int i, perf_runs;
		KeyPairGenerator kg;
		KeyPair kp;
		Signature jce_sig, p11_sig;
		byte[] jce_digest, p11_digest;
		boolean bVerify;
		byte[] sig;

		/* ================  TEST 1 ==================*/
		/* Try generating a hash object first, since keygen takes awhile and we may not
		 * even support this mechanism */
		try {
			jce_sig = java.security.Signature.getInstance(hash, "IBMJCE");
			p11_sig = java.security.Signature.getInstance(hash, provider);
		} catch (Exception e) {
			System.out.println(e);
			return;
		}

		System.out.println("Created a " + hash + " object");

		try {
			kg = KeyPairGenerator.getInstance("RSA", "IBMJCE");
			kg.initialize(key_len);
			kp = kg.generateKeyPair();
		}
		catch (Exception e)
		{
			System.out.println(e);
			return;
		}

		System.out.println("Generated a " + key_len + "-bit JCE key");

		/* sign using JCE */
		try {
			jce_sig.initSign(kp.getPrivate());
			jce_sig.update(data_to_sign);
			sig = jce_sig.sign();
		}
		catch (Exception e)
		{
			System.out.println(e);
			return;
		}

		System.out.println("Signed the " + hash + " object using JCE");

		/* verify using P11 */
		try {
			p11_sig.initVerify(kp.getPublic());
			p11_sig.update(data_to_sign);
			bVerify = p11_sig.verify(sig);
		}
		catch (Exception e)
		{
			System.out.println(e);
			return;
		}

		if (!bVerify) {
			System.out.println("Verification of JCE signature on P11 failed!");
		} else {
			System.out.println("Verified the " + hash + " object using P11: Success!");
		}

		/* ================  TEST 2 ==================*/
		try {
			kg = KeyPairGenerator.getInstance("RSA", provider);
			kg.initialize(key_len);
			kp = kg.generateKeyPair();
		}
		catch (Exception e)
		{
			System.out.println(e);
			return;
		}

		System.out.println("Generated a " + key_len + "-bit P11 key");

		try {
			p11_sig = java.security.Signature.getInstance(hash, provider);
			jce_sig = java.security.Signature.getInstance(hash, "IBMJCE");
		}
		catch (Exception e)
		{
			System.out.println(e);
			return;
		}

		System.out.println("Created a " + hash + " object");

		/* sign using P11 */
		try {
			p11_sig.initSign(kp.getPrivate());
			p11_sig.update(data_to_sign);
			sig = p11_sig.sign();
		}
		catch (Exception e)
		{
			System.out.println(e);
			return;
		}

		System.out.println("Signed the " + hash + " object using P11");

		/* verify using JCE */
		try {
			jce_sig.initVerify(kp.getPublic());
			jce_sig.update(data_to_sign);
			bVerify = jce_sig.verify(sig);
		}
		catch (Exception e)
		{
			System.out.println(e);
			return;
		}

		if (!bVerify) {
			System.out.println("Verification of P11 signature on JCE failed!");
		} else {
			System.out.println("Verified the " + hash + " object using JCE: Success!");
		}
	}


	public static void main(String argv[])
	{
		byte[] data = new byte[139]; /* this data will be hashed */

		if (argv.length != 2)
		{
			System.out.println("usage: opencryptoki_java_test <mechanism> " +
					   "<config file>");
			return;
		}

		opencryptoki_java_test test = new opencryptoki_java_test(argv[1]);

		if (argv[0].equals("CKM_SHA256_RSA_PKCS")) {
			test.sign_verify("SHA256withRSA", 512,  data, "IBMPKCS11Impl-Sample");
			test.sign_verify("SHA256withRSA", 1024, data, "IBMPKCS11Impl-Sample");
			test.sign_verify("SHA256withRSA", 2048, data, "IBMPKCS11Impl-Sample");
			test.sign_verify("SHA256withRSA", 4096, data, "IBMPKCS11Impl-Sample");
		} else if (argv[0].equals("CKM_SHA1_RSA_PKCS")) {
			test.sign_verify("SHA1withRSA", 512,  data, "IBMPKCS11Impl-Sample");
			test.sign_verify("SHA1withRSA", 1024, data, "IBMPKCS11Impl-Sample");
			test.sign_verify("SHA1withRSA", 2048, data, "IBMPKCS11Impl-Sample");
			test.sign_verify("SHA1withRSA", 4096, data, "IBMPKCS11Impl-Sample");
		} else if (argv[0].equals("CKM_MD5_RSA_PKCS")) {
			test.sign_verify("MD5withRSA", 512,  data, "IBMPKCS11Impl-Sample");
			test.sign_verify("MD5withRSA", 1024, data, "IBMPKCS11Impl-Sample");
			test.sign_verify("MD5withRSA", 2048, data, "IBMPKCS11Impl-Sample");
			test.sign_verify("MD5withRSA", 4096, data, "IBMPKCS11Impl-Sample");
		} else {
			System.out.println("Unknown mechanism: " + argv[0]);
		}
	}

	public static void showProviders()
	{
		java.security.Provider[] providers = Security.getProviders();
		System.out.println("\n\n\n================================================");
		System.out.println("The security provider's list is:");
		for (int i=0; i<providers.length; ++i) {
			System.out.print("provider \"");
			System.out.print(providers[i].getName());
			System.out.print("\": ");
			System.out.println(providers[i].toString());
			System.out.println();
		}

		System.out.println("================================================\n\n\n");
	}
}
