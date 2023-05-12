package be.nabu.utils.security;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.nio.charset.Charset;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;

import javax.security.auth.x500.X500Principal;
import javax.xml.XMLConstants;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import junit.framework.TestCase;

public class TestXMLSignatures extends TestCase {
	
	public void testSign() throws SAXException, IOException, ParserConfigurationException, CertificateException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, MarshalException, XMLSignatureException, TransformerException {
		String rawXml = "<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\"\n" + 
				"	xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_8e8dc5f69a98cc4c1ff3427e5ce34606fd672f91e6\" Version=\"2.0\" IssueInstant=\"2014-07-17T01:01:48Z\" Destination=\"http://sp.example.com/demo1/index.php?acs\" InResponseTo=\"ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685\">\n" + 
				"	<saml:Issuer>http://idp.example.com/metadata.php</saml:Issuer>\n" + 
				"	<samlp:Status>\n" + 
				"		<samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/>\n" + 
				"	</samlp:Status>\n" + 
				"	<saml:Assertion xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"\n" + 
				"		xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" ID=\"_d71a3a8e9fcc45c9e9d248ef7049393fc8f04e5f75\" Version=\"2.0\" IssueInstant=\"2014-07-17T01:01:48Z\">\n" + 
				"		<saml:Issuer>http://idp.example.com/metadata.php</saml:Issuer>\n" + 
				"		<saml:Subject>\n" + 
				"			<saml:NameID SPNameQualifier=\"http://sp.example.com/demo1/metadata.php\" Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:transient\">_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7</saml:NameID>\n" + 
				"			<saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">\n" + 
				"				<saml:SubjectConfirmationData NotOnOrAfter=\"2024-01-18T06:21:48Z\" Recipient=\"http://sp.example.com/demo1/index.php?acs\" InResponseTo=\"ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685\"/>\n" + 
				"			</saml:SubjectConfirmation>\n" + 
				"		</saml:Subject>\n" + 
				"		<saml:Conditions NotBefore=\"2014-07-17T01:01:18Z\" NotOnOrAfter=\"2024-01-18T06:21:48Z\">\n" + 
				"			<saml:AudienceRestriction>\n" + 
				"				<saml:Audience>http://sp.example.com/demo1/metadata.php</saml:Audience>\n" + 
				"			</saml:AudienceRestriction>\n" + 
				"		</saml:Conditions>\n" + 
				"		<saml:AuthnStatement AuthnInstant=\"2014-07-17T01:01:48Z\" SessionNotOnOrAfter=\"2024-07-17T09:01:48Z\" SessionIndex=\"_be9967abd904ddcae3c0eb4189adbe3f71e327cf93\">\n" + 
				"			<saml:AuthnContext>\n" + 
				"				<saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>\n" + 
				"			</saml:AuthnContext>\n" + 
				"		</saml:AuthnStatement>\n" + 
				"		<saml:AttributeStatement>\n" + 
				"			<saml:Attribute Name=\"uid\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:basic\">\n" + 
				"				<saml:AttributeValue xsi:type=\"xs:string\">test</saml:AttributeValue>\n" + 
				"			</saml:Attribute>\n" + 
				"			<saml:Attribute Name=\"mail\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:basic\">\n" + 
				"				<saml:AttributeValue xsi:type=\"xs:string\">test@example.com</saml:AttributeValue>\n" + 
				"			</saml:Attribute>\n" + 
				"			<saml:Attribute Name=\"eduPersonAffiliation\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:basic\">\n" + 
				"				<saml:AttributeValue xsi:type=\"xs:string\">users</saml:AttributeValue>\n" + 
				"				<saml:AttributeValue xsi:type=\"xs:string\">examplerole1</saml:AttributeValue>\n" + 
				"			</saml:Attribute>\n" + 
				"		</saml:AttributeStatement>\n" + 
				"	</saml:Assertion>\n" + 
				"</samlp:Response>";
		
		Document document = toDocument(rawXml, Charset.forName("UTF-8"), true);
		KeyPair keyPair = SecurityUtils.generateKeyPair(KeyPairType.RSA, 2048);
		X500Principal principal = SecurityUtils.createX500Principal("test", "test", "test", "test", "test", "test");
		X509Certificate certificate = BCSecurityUtils.generateSelfSignedCertificate(keyPair, new Date(new Date().getTime() + 1000l*60*60*24*30), principal, principal);
		SecurityUtils.signXml(document.getDocumentElement(), keyPair.getPrivate(), certificate, null, null);
		boolean verifyXml = SecurityUtils.verifyXml(document.getDocumentElement(), keyPair.getPublic());
		assertTrue("Check that the XML is valid", verifyXml);
	}
	
	public void testSignAssertion() throws SAXException, IOException, ParserConfigurationException, CertificateException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, MarshalException, XMLSignatureException, TransformerException {
		String rawXml = "<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\"\n" + 
				"	xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_8e8dc5f69a98cc4c1ff3427e5ce34606fd672f91e6\" Version=\"2.0\" IssueInstant=\"2014-07-17T01:01:48Z\" Destination=\"http://sp.example.com/demo1/index.php?acs\" InResponseTo=\"ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685\">\n" + 
				"	<saml:Issuer>http://idp.example.com/metadata.php</saml:Issuer>\n" + 
				"	<samlp:Status>\n" + 
				"		<samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/>\n" + 
				"	</samlp:Status>\n" + 
				"	<saml:Assertion xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"\n" + 
				"		xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" ID=\"_d71a3a8e9fcc45c9e9d248ef7049393fc8f04e5f75\" Version=\"2.0\" IssueInstant=\"2014-07-17T01:01:48Z\">\n" + 
				"		<saml:Issuer>http://idp.example.com/metadata.php</saml:Issuer>\n" + 
				"		<saml:Subject>\n" + 
				"			<saml:NameID SPNameQualifier=\"http://sp.example.com/demo1/metadata.php\" Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:transient\">_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7</saml:NameID>\n" + 
				"			<saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">\n" + 
				"				<saml:SubjectConfirmationData NotOnOrAfter=\"2024-01-18T06:21:48Z\" Recipient=\"http://sp.example.com/demo1/index.php?acs\" InResponseTo=\"ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685\"/>\n" + 
				"			</saml:SubjectConfirmation>\n" + 
				"		</saml:Subject>\n" + 
				"		<saml:Conditions NotBefore=\"2014-07-17T01:01:18Z\" NotOnOrAfter=\"2024-01-18T06:21:48Z\">\n" + 
				"			<saml:AudienceRestriction>\n" + 
				"				<saml:Audience>http://sp.example.com/demo1/metadata.php</saml:Audience>\n" + 
				"			</saml:AudienceRestriction>\n" + 
				"		</saml:Conditions>\n" + 
				"		<saml:AuthnStatement AuthnInstant=\"2014-07-17T01:01:48Z\" SessionNotOnOrAfter=\"2024-07-17T09:01:48Z\" SessionIndex=\"_be9967abd904ddcae3c0eb4189adbe3f71e327cf93\">\n" + 
				"			<saml:AuthnContext>\n" + 
				"				<saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>\n" + 
				"			</saml:AuthnContext>\n" + 
				"		</saml:AuthnStatement>\n" + 
				"		<saml:AttributeStatement>\n" + 
				"			<saml:Attribute Name=\"uid\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:basic\">\n" + 
				"				<saml:AttributeValue xsi:type=\"xs:string\">test</saml:AttributeValue>\n" + 
				"			</saml:Attribute>\n" + 
				"			<saml:Attribute Name=\"mail\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:basic\">\n" + 
				"				<saml:AttributeValue xsi:type=\"xs:string\">test@example.com</saml:AttributeValue>\n" + 
				"			</saml:Attribute>\n" + 
				"			<saml:Attribute Name=\"eduPersonAffiliation\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:basic\">\n" + 
				"				<saml:AttributeValue xsi:type=\"xs:string\">users</saml:AttributeValue>\n" + 
				"				<saml:AttributeValue xsi:type=\"xs:string\">examplerole1</saml:AttributeValue>\n" + 
				"			</saml:Attribute>\n" + 
				"		</saml:AttributeStatement>\n" + 
				"	</saml:Assertion>\n" + 
				"</samlp:Response>";
		
		Document document = toDocument(rawXml, Charset.forName("UTF-8"), true);
		Element assertion = getElement(document.getDocumentElement(), "Assertion");
		KeyPair keyPair = SecurityUtils.generateKeyPair(KeyPairType.RSA, 2048);
		X500Principal principal = SecurityUtils.createX500Principal("test", "test", "test", "test", "test", "test");
		X509Certificate certificate = BCSecurityUtils.generateSelfSignedCertificate(keyPair, new Date(new Date().getTime() + 1000l*60*60*24*30), principal, principal);
		SecurityUtils.signXml(assertion, keyPair.getPrivate(), certificate, null, null);
		boolean verifyXml = SecurityUtils.verifyXml(document.getDocumentElement(), "Assertion/Signature", keyPair.getPublic());
		assertTrue("Check that the XML is valid", verifyXml);
	}
	
	public static Element getElement(Element element, String path) {
		String[] parts = path.replaceFirst("^[/]+$", "").split("/");
		search: for (String part : parts) {
			NodeList childNodes = element.getChildNodes();
			for (int i = 0; i < childNodes.getLength(); i++) {
				Node item = childNodes.item(i);
				if (item instanceof Element && ((Element) item).getLocalName().equalsIgnoreCase(part)) {
					element = (Element) item;
					continue search;
				}
			}
			throw new IllegalArgumentException("Could not resolve '" + part + "' of signature path '" + path + "'");
		}
		return element;
	}
	
	public static Document toDocument(InputStream xml, boolean namespaceAware) throws SAXException, IOException, ParserConfigurationException {
		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		// no DTD
		factory.setValidating(false);
		factory.setNamespaceAware(namespaceAware);
		factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
		// allow no external access, as defined http://docs.oracle.com/javase/7/docs/api/javax/xml/XMLConstants.html#FEATURE_SECURE_PROCESSING an empty string means no protocols are allowed
		try {
			factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
		}
		catch (Exception e) {
			// not supported in later versions..............
		}
		return factory.newDocumentBuilder().parse(xml);
	}
	
	public static Document toDocument(String xml, Charset encoding, boolean namespaceAware) throws SAXException, IOException, ParserConfigurationException {
		InputStream input = new ByteArrayInputStream(xml.getBytes(encoding));
		return toDocument(input, namespaceAware);
	}
	
	public static String toString(Node node, boolean omitXMLDeclaration, boolean prettyPrint) throws TransformerException {
        StringWriter string = new StringWriter();
        TransformerFactory factory = TransformerFactory.newInstance();
        Transformer transformer = factory.newTransformer();
        if (omitXMLDeclaration) {
        	transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
        }
        if (prettyPrint) {
        	transformer.setOutputProperty(OutputKeys.INDENT, "yes");
        }
        transformer.transform(new DOMSource(node), new StreamResult(string));
        return string.toString();
	}
}
