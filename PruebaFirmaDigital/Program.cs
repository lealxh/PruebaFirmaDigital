using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PruebaFirmaDigital
{
    class Program
    {
        static void Main(string[] args)
        {
    
    

            Console.WriteLine("Ingrese la data a firmar:");
            string sourceData = Console.ReadLine();

            byte[] tmpSource = ASCIIEncoding.ASCII.GetBytes(sourceData);

            
            Console.WriteLine();
            Console.WriteLine();
            Console.WriteLine("Generando llaves publica y privada por favor espere..");
            Console.WriteLine();

            RsaKeyPairGenerator rsaKeyPairGen = new RsaKeyPairGenerator();
            rsaKeyPairGen.Init(new Org.BouncyCastle.Crypto.KeyGenerationParameters(new Org.BouncyCastle.Security.SecureRandom(),2048)) ;
            AsymmetricCipherKeyPair keys = rsaKeyPairGen.GenerateKeyPair();
            RsaKeyParameters publicKey = (RsaKeyParameters)keys.Public;
            RsaKeyParameters privateKey = (RsaKeyParameters)keys.Private;


            TextWriter writter = new StringWriter();
            PemWriter pemWritter = new PemWriter(writter);
            pemWritter.WriteObject(publicKey);
            pemWritter.Writer.Flush();

            string publicKeyString = writter.ToString();
            Console.WriteLine("La llave publica es:");
            Console.WriteLine(publicKeyString);

            ISigner signer = Org.BouncyCastle.Security.SignerUtilities.GetSigner(PkcsObjectIdentifiers.Sha512WithRsaEncryption.Id);
            signer.Init(true, privateKey);
            signer.BlockUpdate(tmpSource, 0, tmpSource.Length);
            byte[] signature = signer.GenerateSignature();

            Console.WriteLine();
            Console.WriteLine("La data firmada es:");
            
            Console.WriteLine(System.Web.HttpServerUtility.UrlTokenEncode(signature));
            Console.WriteLine();


            ISigner signer2 = Org.BouncyCastle.Security.SignerUtilities.GetSigner(PkcsObjectIdentifiers.Sha1WithRsaEncryption.Id);
            signer2.Init(false, publicKey);
            signer2.BlockUpdate(tmpSource, 0, tmpSource.Length);

            bool result = signer2.VerifySignature(signature);
            

            Console.WriteLine();

            Console.WriteLine("Resultado de la verificacion de la firma:");
            if(result)
            Console.WriteLine("La firma es correcta.");
            else
            Console.WriteLine("La firma es incorrecta.");

            Console.WriteLine();
            Console.WriteLine("Reintentando.. ");


            ISigner signer3 = Org.BouncyCastle.Security.SignerUtilities.GetSigner(PkcsObjectIdentifiers.Sha512WithRsaEncryption.Id);
            signer3.Init(false, publicKey);
            signer3.BlockUpdate(tmpSource, 0, tmpSource.Length);

            result = signer3.VerifySignature(signature);

        

            Console.WriteLine();

            Console.WriteLine("Resultado de la verificacion de la firma:");
            if (result)
                Console.WriteLine("La firma es correcta.");
            else
                Console.WriteLine("La firma es incorrecta.");

            Console.ReadLine();







        }

        static AsymmetricKeyParameter readPrivateKey(string privateKeyFileName)
        {
            AsymmetricCipherKeyPair keyPair;

            using (var reader = File.OpenText(privateKeyFileName))
                keyPair = (AsymmetricCipherKeyPair)new PemReader(reader).ReadObject();

            return keyPair.Private;
        }

       
    }
}
