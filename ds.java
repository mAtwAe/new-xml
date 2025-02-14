package com.api.invoice.service;
/**************************************************************************************
 * THIS SAMPLE CODE COMES WITHOUT ANY WARRANTY.
 *
 * YOU ARE FREE TO ALTER AT ANY TIME BASED ON YOUR SYSTEM REQUIREMENT,
 * WHERE APPROPRIATE.
 *
 * THE SAMPLE CODE IS BASED ON JAVA 1.8 USING STANDARD JAVA LIBRARY.
 * NO ANY THIRD PARTY LIBRARY IS REQUIRED TO RUN THIS SAMPLE CODE.
 *
 * YOU MIGHT WANT TO USE THIRD PARTY LIBRARIES TO EASE DEVELOPMENT,
 * IN ADDIITON TO THIS SAMPLE CODE.
 *************************************************************************************/

import com.api.invoice.constants.Constants;
import com.api.invoice.model.DigitalSigDTO;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

@Service
public class ReadSoftcertService {
    private static final Logger logger = LoggerFactory.getLogger(ReadSoftcertService.class);

    public DigitalSigDTO readSoftcertJSON(byte[] documentBytes) throws NoSuchAlgorithmException {

        DigitalSigDTO digitalSigDTO = new DigitalSigDTO();

        String PIN = "";
        String softcertFile = "";

//        String dataToSign = docdigest;
        //Step 2 Calculate the document digest , //DigestValue
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(documentBytes);
        String docdigest = Base64.getEncoder().encodeToString(hash);
        digitalSigDTO.setDocDigest(docdigest);

        byte[] signData = null;
        byte[] softcertBytes = null;
        PrivateKey privateKey = null;
        String alias = "";
        X509Certificate x509 = null;

        try {

            /****************************************************************************
             * 1. Read soft-cert into bytes
             ***************************************************************************/
            softcertBytes = Files.readAllBytes(Paths.get(softcertFile));
            KeyStore store = ReadSoftcertService.loadKeyStore(softcertBytes, PIN);

            /****************************************************************************
             * 2. Find private key and user x509 certificate
             ***************************************************************************/
            Enumeration<String> e = store.aliases();
            for (; e.hasMoreElements();) {

                alias = (String) e.nextElement();

                if (store.isKeyEntry(alias)) {
                    privateKey = (PrivateKey) store.getKey(alias, PIN.toCharArray());

                    x509 =  (X509Certificate) store.getCertificate(alias);
                    CertificateFactory cf = CertificateFactory.getInstance("X.509");
                    x509 = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(x509.getEncoded()));

                    //print certificate details
                    System.out.println(x509.toString());

                    //write x509 certificate into file
                    Files.write(Paths.get("x509.cer"), x509.getEncoded());
                }

            }

            // Step 3 Sign the document digest using the certificate  //Signature value
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(privateKey);
            signature.update(documentBytes);
            byte[] sign = signature.sign();
            String base64Signature = java.util.Base64.getEncoder().encodeToString(sign);
            digitalSigDTO.setSignData(base64Signature);


            /****************************************************************************
             * 3. Perform signing with SHA256RSA algorithm
             ***************************************************************************/
//            Signature sig = Signature.getInstance("SHA256withRSA");
//            sig.initSign(privateKey);
//            sig.update(dataToSign.getBytes());

//            signData = sig.sign();

            /****************************************************************************
             * 4. Convert signed data and x509 certificate to Base64 format
             ***************************************************************************/

            // Compute the SHA-256 hash of the certificate
            Certificate cert = x509;
            String certBase64 = Base64.getEncoder().encodeToString(cert.getEncoded());
            byte[] certDigestHash = digest.digest(cert.getEncoded());
            String certDigestBase64 = Base64.getEncoder().encodeToString(certDigestHash);
            digitalSigDTO.setCertDigestBase64(certDigestBase64);
            digitalSigDTO.setX509Certificate(certBase64);

            X509Certificate x509Cert = (X509Certificate) cert;
            String subjectName = ((X509Certificate) cert).getSubjectX500Principal().getName();
            digitalSigDTO.setX509Subject(subjectName);
            String issuerDn = x509Cert.getIssuerX500Principal().getName();
//            String issuerCn = extractField(issuerDn, "CN");
//            String issuerO = extractField(issuerDn, "O");
//            String issuerC = extractField(issuerDn, "C");
            String issuerName = x509Cert.getIssuerDN().getName();
            digitalSigDTO.setX509IssuerName(issuerName);

            String serialNumber = x509Cert.getSerialNumber().toString();
            digitalSigDTO.setX509SerialNumber(serialNumber);

//            String signedData = new String(Base64.getEncoder().encode(signData));
//            logger.info("\n SignatureValue : " + signedData);
//            digitalSigDTO.setSignData(signedData);
//
//            String certBase64Calculated = calculateSHA256Base64(x509.getEncoded());
//            digitalSigDTO.setCertDigestBase64(certBase64Calculated);
//
//            String certBase64 = new String(Base64.getEncoder().encode(x509.getEncoded()));
//            logger.info("\n X509Certificate : " + certBase64);
//            digitalSigDTO.setX509Certificate(certBase64);
//
//            String X509IssuerName = x509.getIssuerDN().getName();
//            logger.info("\n X509IssuerName : " + X509IssuerName);
//            digitalSigDTO.setX509IssuerName(X509IssuerName);
//
//            String subject = x509.getSubjectX500Principal().getName();
//            logger.info("\n X509subject : " + subject);
//            digitalSigDTO.setX509Subject(subject);
//
//            String x509SerialNumber = x509.getSerialNumber() + "";
//            logger.info("\n x509SerialNumber : " + x509SerialNumber);
//            digitalSigDTO.setX509SerialNumber(x509SerialNumber);



        } catch (IOException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (UnrecoverableKeyException e1) {
            e1.printStackTrace();
        } catch (InvalidKeyException e1) {
            e1.printStackTrace();
        } catch (SignatureException e1) {
            e1.printStackTrace();
        }

        return digitalSigDTO;
    }

    public List<Map<String, Object>> populateSignProperties(DigitalSigDTO digitalSigDTO){
        String result = "";
        List<Map<String, Object>> ublExtensions = new ArrayList<>();

        // Create the root HashMap
        Map<String, Object> root = new LinkedHashMap<>();
        try {

            ZonedDateTime malaysiaTime = ZonedDateTime.now(ZoneId.of("Asia/Kuala_Lumpur"));
            ZonedDateTime newTime = malaysiaTime.minusMinutes(5);

            // Print the current date and time in UTC
            // Format the date and time
            DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss'Z'");
            String formattedDateTime = newTime.format(formatter);

            // Create the SignedProperties list
            List<Map<String, Object>> signedProperties = new ArrayList<>();
            Map<String, Object> signedProperty = new LinkedHashMap<>();
            signedProperty.put("Id", "id-xades-signed-props");

            // Create SignedSignatureProperties list
            List<Map<String, Object>> signedSignatureProperties = new ArrayList<>();
            Map<String, Object> signedSignatureProperty = new LinkedHashMap<>();

            // SigningTime
            List<Map<String, String>> signingTimeList = new ArrayList<>();
            Map<String, String> signingTime = new LinkedHashMap<>();
            signingTime.put("_", formattedDateTime);
            signingTimeList.add(signingTime);
            signedSignatureProperty.put("SigningTime", signingTimeList);

            // SigningCertificate
            List<Map<String, Object>> signingCertificateList = new ArrayList<>();
            Map<String, Object> signingCertificate = new LinkedHashMap<>();

            // Cert
            List<Map<String, Object>> certList = new ArrayList<>();
            Map<String, Object> cert = new LinkedHashMap<>();

            // CertDigest
            List<Map<String, Object>> certDigestList = new ArrayList<>();
            Map<String, Object> certDigest = new LinkedHashMap<>();

            // DigestMethod
            List<Map<String, String>> digestMethodList = new ArrayList<>();
            Map<String, String> digestMethod = new LinkedHashMap<>();
            digestMethod.put("_", "");
            digestMethod.put("Algorithm", "http://www.w3.org/2001/04/xmlenc#sha256");
            digestMethodList.add(digestMethod);
            certDigest.put("DigestMethod", digestMethodList);

            // DigestValue
            List<Map<String, String>> digestValueList = new ArrayList<>();
            Map<String, String> digestValue = new LinkedHashMap<>();
            digestValue.put("_", digitalSigDTO.getCertDigestBase64());
            digestValueList.add(digestValue);
            certDigest.put("DigestValue", digestValueList);

            certDigestList.add(certDigest);
            cert.put("CertDigest", certDigestList);

            // IssuerSerial
            List<Map<String, Object>> issuerSerialList = new ArrayList<>();
            Map<String, Object> issuerSerial = new LinkedHashMap<>();

            // X509IssuerName
            List<Map<String, String>> issuerNameList = new ArrayList<>();
            Map<String, String> issuerName = new LinkedHashMap<>();
            issuerName.put("_", digitalSigDTO.getX509IssuerName());
            issuerNameList.add(issuerName);
            issuerSerial.put("X509IssuerName", issuerNameList);

            // X509SerialNumber
            List<Map<String, String>> serialNumberList = new ArrayList<>();
            Map<String, String> serialNumber = new LinkedHashMap<>();
            serialNumber.put("_", digitalSigDTO.getX509SerialNumber());
            serialNumberList.add(serialNumber);
            issuerSerial.put("X509SerialNumber", serialNumberList);

            issuerSerialList.add(issuerSerial);
            cert.put("IssuerSerial", issuerSerialList);
            certList.add(cert);
            signingCertificate.put("Cert", certList);
            signingCertificateList.add(signingCertificate);
            signedSignatureProperty.put("SigningCertificate", signingCertificateList);
            signedSignatureProperties.add(signedSignatureProperty);
            signedProperty.put("SignedSignatureProperties", signedSignatureProperties);
            signedProperties.add(signedProperty);
            root.put("SignedProperties", signedProperties);

            // Convert HashMap to JSON
            ObjectMapper objectMapper = new ObjectMapper();


            ArrayList<Object> signatureJson = new ArrayList<>();
            Map<String, Object> signatureJsonMap = new LinkedHashMap<>();
            String target = "signature";
            signatureJsonMap.put("Target",target);
            signatureJsonMap.put("SignedProperties", List.of(root));
            signatureJson.add(signatureJsonMap);

            //Step 6: Calculate the signed properties section digest  //propsdigest
            ObjectMapper mapper = new ObjectMapper();
            String signatureJsonResult = mapper.writerWithDefaultPrettyPrinter()
                    .writeValueAsString(signatureJson.getFirst());
            JsonNode signatureJsonNode = mapper.readValue(signatureJsonResult, JsonNode.class);
            String minifiedSignature = signatureJsonNode.toString(); // minified.
            logger.info(minifiedSignature);
            // Compute SHA-256 hash
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] signatureHash = digest.digest(minifiedSignature.getBytes(StandardCharsets.UTF_8));
            // Convert hash to Base64
            String propsdigest = Base64.getEncoder().encodeToString(signatureHash);
            digitalSigDTO.setPropsDigest(propsdigest);

            /// ///////////////////////////////////////

            // Create root HashMap
            Map<String, Object> rootUbl = new LinkedHashMap<>();

            // Create the UBLExtensions list
//            List<Map<String, Object>> ublExtensions = new ArrayList<>();
            Map<String, Object> ublExtensionWrapper = new LinkedHashMap<>();
            List<Map<String, Object>> ublExtensionList = new ArrayList<>();
            Map<String, Object> ublExtension = new LinkedHashMap<>();

            // ExtensionURI
            List<Map<String, String>> extensionURIList = new ArrayList<>();
            Map<String, String> extensionURI = new LinkedHashMap<>();
            extensionURI.put("_", "urn:oasis:names:specification:ubl:dsig:enveloped:xades");
            extensionURIList.add(extensionURI);
            ublExtension.put("ExtensionURI", extensionURIList);

            // ExtensionContent
            List<Map<String, Object>> extensionContentList = new ArrayList<>();
            Map<String, Object> extensionContent = new LinkedHashMap<>();

            // UBLDocumentSignatures
            List<Map<String, Object>> ublDocumentSignaturesList = new ArrayList<>();
            Map<String, Object> ublDocumentSignatures = new LinkedHashMap<>();

            // SignatureInformation
            List<Map<String, Object>> signatureInformationList = new ArrayList<>();
            Map<String, Object> signatureInformation = new LinkedHashMap<>();

            // ID
            List<Map<String, String>> idList = new ArrayList<>();
            Map<String, String> id = new LinkedHashMap<>();
            id.put("_", "urn:oasis:names:specification:ubl:signature:1");
            idList.add(id);
            signatureInformation.put("ID", idList);

            // ReferencedSignatureID
            List<Map<String, String>> referencedSignatureIDList = new ArrayList<>();
            Map<String, String> referencedSignatureID = new LinkedHashMap<>();
            referencedSignatureID.put("_", "urn:oasis:names:specification:ubl:signature:Invoice");
            referencedSignatureIDList.add(referencedSignatureID);
            signatureInformation.put("ReferencedSignatureID", referencedSignatureIDList);

            // Signature
            List<Map<String, Object>> signatureList = new ArrayList<>();
            Map<String, Object> signature = new LinkedHashMap<>();
            signature.put("Id", "signature");

            // Object
            List<Map<String, Object>> objectList = new ArrayList<>();
            Map<String, Object> object = new LinkedHashMap<>();

            // QualifyingProperties
            List<Map<String, Object>> qualifyingPropertiesList = new ArrayList<>();
            Map<String, Object> qualifyingProperties = new LinkedHashMap<>();
            qualifyingProperties.put("Target", "signature");
            qualifyingProperties.put("SignedProperties", signedProperties);
            qualifyingPropertiesList.add(qualifyingProperties);
            object.put("QualifyingProperties", qualifyingPropertiesList);
            objectList.add(object);
            signature.put("Object", objectList);

            // KeyInfo
            List<Map<String, Object>> keyInfoList = new ArrayList<>();
            Map<String, Object> keyInfo = new LinkedHashMap<>();

            // X509Data
            List<Map<String, Object>> x509DataList = new ArrayList<>();
            Map<String, Object> x509Data = new LinkedHashMap<>();

            // X509Certificate
            List<Map<String, String>> x509CertificateList = new ArrayList<>();
            Map<String, String> x509Certificate = new LinkedHashMap<>();
            x509Certificate.put("_", digitalSigDTO.getX509Certificate());
            x509CertificateList.add(x509Certificate);
            x509Data.put("X509Certificate", x509CertificateList);

            // X509SubjectName
            List<Map<String, String>> x509SubjectNameList = new ArrayList<>();
            Map<String, String> x509SubjectName = new LinkedHashMap<>();
            x509SubjectName.put("_", digitalSigDTO.getX509Subject());
            x509SubjectNameList.add(x509SubjectName);
            x509Data.put("X509SubjectName", x509SubjectNameList);

            // X509IssuerSerial
            List<Map<String, Object>> x509IssuerSerialList = new ArrayList<>();
            Map<String, Object> x509IssuerSerial = new LinkedHashMap<>();

            // X509IssuerName
            List<Map<String, String>> x509IssuerNameList = new ArrayList<>();
            Map<String, String> x509IssuerName = new LinkedHashMap<>();
            x509IssuerName.put("_", digitalSigDTO.getX509IssuerName());
            x509IssuerNameList.add(x509IssuerName);
            x509IssuerSerial.put("X509IssuerName", x509IssuerNameList);

            // X509SerialNumber
            List<Map<String, String>> x509SerialNumberList = new ArrayList<>();
            Map<String, String> x509SerialNumber = new LinkedHashMap<>();
            x509SerialNumber.put("_", digitalSigDTO.getX509SerialNumber());
            x509SerialNumberList.add(x509SerialNumber);
            x509IssuerSerial.put("X509SerialNumber", x509SerialNumberList);
            x509IssuerSerialList.add(x509IssuerSerial);
            x509Data.put("X509IssuerSerial", x509IssuerSerialList);
            x509DataList.add(x509Data);
            keyInfo.put("X509Data", x509DataList);
            keyInfoList.add(keyInfo);
            signature.put("KeyInfo", keyInfoList);

            // SignatureValue
            List<Map<String, String>> signatureValueList = new ArrayList<>();
            Map<String, String> signatureValue = new LinkedHashMap<>();
            signatureValue.put("_", digitalSigDTO.getSignData());
            signatureValueList.add(signatureValue);
            signature.put("SignatureValue", signatureValueList);

            // SignedInfo
            List<Map<String, Object>> signedInfoList = new ArrayList<>();
            Map<String, Object> signedInfo = new LinkedHashMap<>();

            // SignatureMethod
            List<Map<String, String>> signatureMethodList = new ArrayList<>();
            Map<String, String> signatureMethod = new LinkedHashMap<>();
            signatureMethod.put("_", "");
            signatureMethod.put("Algorithm", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
            signatureMethodList.add(signatureMethod);
            signedInfo.put("SignatureMethod", signatureMethodList);

            // Reference
            List<Map<String, Object>> referenceList = new ArrayList<>();

            // First Reference
            Map<String, Object> reference1 = new LinkedHashMap<>();
            reference1.put("Id", "id-doc-signed-data");
//            reference1.put("Type", "http://uri.etsi.org/01903/v1.3.2#SignedProperties");
            reference1.put("URI", "");

            List<Map<String, String>> digestMethodList1 = new ArrayList<>();
            Map<String, String> digestMethod1 = new LinkedHashMap<>();
            digestMethod1.put("_", "");
            digestMethod1.put("Algorithm", "http://www.w3.org/2001/04/xmlenc#sha256");
            digestMethodList1.add(digestMethod1);
            reference1.put("DigestMethod", digestMethodList1);

            List<Map<String, String>> digestValueList1 = new ArrayList<>();
            Map<String, String> digestValue1 = new LinkedHashMap<>();
            digestValue1.put("_", digitalSigDTO.getPropsDigest());
//            digestValue1.put("_", digitalSigDTO.getDocDigest());
            digestValueList1.add(digestValue1);
            reference1.put("DigestValue", digestValueList1);

            referenceList.add(reference1);

            // Second Reference
            Map<String, Object> reference2 = new LinkedHashMap<>();
            reference2.put("Id", "#id-xades-signed-props");
            reference2.put("Type", "http://uri.etsi.org/01903/v1.3.2#SignedProperties");
            reference2.put("URI", "#id-xades-signed-props");

            List<Map<String, String>> digestMethodList2 = new ArrayList<>();
            Map<String, String> digestMethod2 = new LinkedHashMap<>();
            digestMethod2.put("_", "");
            digestMethod2.put("Algorithm", "http://www.w3.org/2001/04/xmlenc#sha256");
            digestMethodList2.add(digestMethod2);
            reference2.put("DigestMethod", digestMethodList2);

            List<Map<String, String>> digestValueList2 = new ArrayList<>();
            Map<String, String> digestValue2 = new LinkedHashMap<>();
//            digestValue2.put("_", digitalSigDTO.getPropsDigest());
            digestValue2.put("_", digitalSigDTO.getDocDigest());
            digestValueList2.add(digestValue2);
            reference2.put("DigestValue", digestValueList2);

            referenceList.add(reference2);
            signedInfo.put("Reference", referenceList);
            signedInfoList.add(signedInfo);
            signature.put("SignedInfo", signedInfoList);

            signatureList.add(signature);
            signatureInformation.put("Signature", signatureList);
            signatureInformationList.add(signatureInformation);
            ublDocumentSignatures.put("SignatureInformation", signatureInformationList);
            ublDocumentSignaturesList.add(ublDocumentSignatures);
            extensionContent.put("UBLDocumentSignatures", ublDocumentSignaturesList);
            extensionContentList.add(extensionContent);
            ublExtension.put("ExtensionContent", extensionContentList);
            ublExtensionList.add(ublExtension);
            ublExtensionWrapper.put("UBLExtension", ublExtensionList);
            ublExtensions.add(ublExtensionWrapper);
            rootUbl.put("UBLExtensions", ublExtensions);
            result =  objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(rootUbl);
            logger.info(result);


        } catch (Exception e) {
            e.printStackTrace();
        }
        return ublExtensions;
    }

    private void populateUblExtension(){

        try {
            // Create root HashMap
            Map<String, Object> rootUbl = new LinkedHashMap<>();

            // Create the UBLExtensions list
            List<Map<String, Object>> ublExtensions = new ArrayList<>();
            Map<String, Object> ublExtensionWrapper = new LinkedHashMap<>();
            List<Map<String, Object>> ublExtensionList = new ArrayList<>();
            Map<String, Object> ublExtension = new LinkedHashMap<>();

            // ExtensionURI
            List<Map<String, String>> extensionURIList = new ArrayList<>();
            Map<String, String> extensionURI = new LinkedHashMap<>();
            extensionURI.put("_", "urn:oasis:names:specification:ubl:dsig:enveloped:xades");
            extensionURIList.add(extensionURI);
            ublExtension.put("ExtensionURI", extensionURIList);

            // ExtensionContent
            List<Map<String, Object>> extensionContentList = new ArrayList<>();
            Map<String, Object> extensionContent = new LinkedHashMap<>();

            // UBLDocumentSignatures
            List<Map<String, Object>> ublDocumentSignaturesList = new ArrayList<>();
            Map<String, Object> ublDocumentSignatures = new LinkedHashMap<>();

            // SignatureInformation
            List<Map<String, Object>> signatureInformationList = new ArrayList<>();
            Map<String, Object> signatureInformation = new LinkedHashMap<>();

            // ID
            List<Map<String, String>> idList = new ArrayList<>();
            Map<String, String> id = new LinkedHashMap<>();
            id.put("_", "urn:oasis:names:specification:ubl:signature:1");
            idList.add(id);
            signatureInformation.put("ID", idList);

            // ReferencedSignatureID
            List<Map<String, String>> referencedSignatureIDList = new ArrayList<>();
            Map<String, String> referencedSignatureID = new LinkedHashMap<>();
            referencedSignatureID.put("_", "urn:oasis:names:specification:ubl:signature:Invoice");
            referencedSignatureIDList.add(referencedSignatureID);
            signatureInformation.put("ReferencedSignatureID", referencedSignatureIDList);

            // Signature
            List<Map<String, Object>> signatureList = new ArrayList<>();
            Map<String, Object> signature = new LinkedHashMap<>();
            signature.put("Id", "signature");

            // Object
            List<Map<String, Object>> objectList = new ArrayList<>();
            Map<String, Object> object = new LinkedHashMap<>();

            // QualifyingProperties
            List<Map<String, String>> qualifyingPropertiesList = new ArrayList<>();
            Map<String, String> qualifyingProperties = new LinkedHashMap<>();
            qualifyingProperties.put("Target", "signature");
            qualifyingPropertiesList.add(qualifyingProperties);
            object.put("QualifyingProperties", qualifyingPropertiesList);
            objectList.add(object);
            signature.put("Object", objectList);

            // KeyInfo
            List<Map<String, Object>> keyInfoList = new ArrayList<>();
            Map<String, Object> keyInfo = new LinkedHashMap<>();

            // X509Data
            List<Map<String, Object>> x509DataList = new ArrayList<>();
            Map<String, Object> x509Data = new LinkedHashMap<>();

            // X509Certificate
            List<Map<String, String>> x509CertificateList = new ArrayList<>();
            Map<String, String> x509Certificate = new LinkedHashMap<>();
            x509Certificate.put("_", "");
            x509CertificateList.add(x509Certificate);
            x509Data.put("X509Certificate", x509CertificateList);

            // X509SubjectName
            List<Map<String, String>> x509SubjectNameList = new ArrayList<>();
            Map<String, String> x509SubjectName = new LinkedHashMap<>();
            x509SubjectName.put("_", "CN=Trial LHDNM Sub CA V1, OU=Terms of use at http://www.posdigicert.com.my, O=LHDNM, C=MY");
            x509SubjectNameList.add(x509SubjectName);
            x509Data.put("X509SubjectName", x509SubjectNameList);

            // X509IssuerSerial
            List<Map<String, Object>> x509IssuerSerialList = new ArrayList<>();
            Map<String, Object> x509IssuerSerial = new LinkedHashMap<>();

            // X509IssuerName
            List<Map<String, String>> x509IssuerNameList = new ArrayList<>();
            Map<String, String> x509IssuerName = new LinkedHashMap<>();
            x509IssuerName.put("_", "CN=Trial LHDNM Sub CA V1, OU=Terms of use at http://www.posdigicert.com.my, O=LHDNM, C=MY");
            x509IssuerNameList.add(x509IssuerName);
            x509IssuerSerial.put("X509IssuerName", x509IssuerNameList);

            // X509SerialNumber
            List<Map<String, String>> x509SerialNumberList = new ArrayList<>();
            Map<String, String> x509SerialNumber = new LinkedHashMap<>();
            x509SerialNumber.put("_", "162880276254639189035871514749820882117");
            x509SerialNumberList.add(x509SerialNumber);
            x509IssuerSerial.put("X509SerialNumber", x509SerialNumberList);
            x509IssuerSerialList.add(x509IssuerSerial);
            x509Data.put("X509IssuerSerial", x509IssuerSerialList);
            x509DataList.add(x509Data);
            keyInfo.put("X509Data", x509DataList);
            keyInfoList.add(keyInfo);
            signature.put("KeyInfo", keyInfoList);

            // SignatureValue
            List<Map<String, String>> signatureValueList = new ArrayList<>();
            Map<String, String> signatureValue = new LinkedHashMap<>();
            signatureValue.put("_", "QTvntg4opuS7ZYWmly/iAO2OnLVJcKylYuF+QJKZdx9BkFVglmVuFtEtwoqgNsbsKaaEDinTSUAVStRJs2tiU1Jdryd4hoZ/Hc5TAvFnThpauVOLsc3j07cUB1+zhNjENmFeI9yzTGjr8XfNi4mNPspnhFAT4QGbRpxkWiIsKj762p3dhCwUNAuNLjunVaosYQ5lvSzGt4B9TF/1xJ7Z6kdcJTmBeltTWErSRA2EOMzWsGWGZVvyPLnXfnlIBQItTvARXveafxFdS1iw91g7mSEEYeqEviI0b4FUmkwH8ed0boFc6EHl1VF+2uVxBtHeKf31FqTQl/6/pF4Qgpn6Hg==");
            signatureValueList.add(signatureValue);
            signature.put("SignatureValue", signatureValueList);
            signatureList.add(signature);
            signatureInformation.put("Signature", signatureList);
            signatureInformationList.add(signatureInformation);
            ublDocumentSignatures.put("SignatureInformation", signatureInformationList);
            ublDocumentSignaturesList.add(ublDocumentSignatures);
            extensionContent.put("UBLDocumentSignatures", ublDocumentSignaturesList);
            extensionContentList.add(extensionContent);
            ublExtension.put("ExtensionContent", extensionContentList);
            ublExtensionList.add(ublExtension);
            ublExtensionWrapper.put("UBLExtension", ublExtensionList);
            ublExtensions.add(ublExtensionWrapper);
            rootUbl.put("UBLExtensions", ublExtensions);

            // Convert HashMap to JSON
            ObjectMapper objectMapper = new ObjectMapper();
            String jsonString = objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(rootUbl);

            // Print JSON
            System.out.println(jsonString);

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }


    public static KeyStore loadKeyStore(byte[] fileInBytes, String PIN)
            throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException
    {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(new ByteArrayInputStream(fileInBytes), PIN.toCharArray());

        return keyStore;

    }

    private String calculateSHA256Base64(byte[] input){
        try{
            MessageDigest digest = MessageDigest.getInstance("SHA-256");

            byte[] hashByte = digest.digest(input);
            return Base64.getEncoder().encodeToString(hashByte);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }



}
