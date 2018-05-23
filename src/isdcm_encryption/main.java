package isdcm_encryption;

import java.io.File;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Result;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import org.apache.xml.security.encryption.XMLCipher;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.slf4j.*;

public class main {

private static final String SECRET_KEY = "mwvFnl2u4YAmFRcp";
    
    public enum ExecutionMode {
        Encrypt,
        Decrypt,
        Help,
        Other
    }
    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        
        ExecutionMode mode = ExecutionMode.Other;
        String inputFile = null;
        String outputFile = null;
        String nodeName = null;
        boolean onlyContent = false;
        
        try
        {
            if (args.length > 0)
            { 
                for (int i = 0; i < args.length; ++i)
                {
                    switch (args[i]) {
                        case "-e":
                            mode = ExecutionMode.Encrypt;
                            break;
                        case "-c":
                        	onlyContent = true;
                            break;
                        case "-d":
                            mode = ExecutionMode.Decrypt;
                            break;
                        case "--help":
                            mode = ExecutionMode.Help;
                            break;
                        case "-i":
                            if (args.length >= i+1) inputFile = args[++i];
                            else throw new Exception("Missing input file, --help for more info.");
                            break;
                        case "-o":
                            if (args.length >= i+1) outputFile = args[++i];
                            else throw new Exception("Missing output file, --help for more info.");
                            break;
                        case "-n":
                            if (args.length >= i+1) nodeName = args[++i];
                            else throw new Exception("Missing node name, --help for more info.");
                            break;
                        default:
                            throw new Exception("Options not recognized, --help for more info.");
                    }
                }
            }
            else throw new Exception("Missing arguments, --help for more info.");
            
            if (mode.equals(ExecutionMode.Encrypt) || mode.equals(ExecutionMode.Decrypt)) {
                if (inputFile == null || outputFile == null) {
                    throw new Exception("Input/Output files are not specified, --help for more info.");
                }
                else {
                	org.apache.xml.security.Init.init();
                }
            }
        }
        catch (Exception ex) {
            System.out.println(ex.getMessage());
            System.exit(2);
        }
        
        try
        {
            switch (mode) {
                case Encrypt:
                    encrypt(inputFile, nodeName, outputFile, onlyContent);
                    break;
                case Decrypt:
                    decrypt(inputFile, outputFile, onlyContent);
                    break;
                case Help:
                    printHelp();
                    break;
                default:
                    throw new Exception("Execution mode not recognized");
            }
        }
        catch (Exception ex) {
            System.out.println("Problems performing encrypting tasks. " + ex.getLocalizedMessage());
            System.exit(1);
        }
        
        System.exit(0);
    }

    private static void encrypt(String inputFile, String nodeName, String outputFile, boolean encryptContentsOnly) throws Exception {
        XMLCipher keyCipher = XMLCipher.getInstance(XMLCipher.AES_128);
        SecretKey symmetricKey = new SecretKeySpec(SECRET_KEY.getBytes(), "AES");
        keyCipher.init(XMLCipher.ENCRYPT_MODE, symmetricKey);
        Document doc = getXMLDocument(inputFile);

        if (nodeName != null)
        {
            NodeList list = doc.getElementsByTagName(nodeName);
            for (int i = 0; i < list.getLength(); ++i)
            {
                doc = (Document) keyCipher.doFinal(list.item(i).getOwnerDocument(), (Element)list.item(i), encryptContentsOnly);
            }         
        }
        else
        {
            doc = keyCipher.doFinal(doc, (Element)doc.getDocumentElement(), encryptContentsOnly);
        }            
        
        saveXMLDocument(doc, outputFile);
    }

    private static void decrypt(String inputFile, String outputFile, boolean encByContent) throws Exception {
        XMLCipher keyCipher = XMLCipher.getInstance(XMLCipher.AES_128);
        SecretKey symmetricKey = new SecretKeySpec(SECRET_KEY.getBytes(), "AES");
        keyCipher.init(XMLCipher.DECRYPT_MODE, symmetricKey);
        
        Document doc = getXMLDocument(inputFile);
        
        NodeList list = findXMLNodes(doc, "*[local-name()='EncryptedData']");
        System.out.println("Items found: " + list.getLength());

        for (int i = 0; i < list.getLength(); ++i)
        {
        	Element elem = (Element)list.item(i);
        	if (encByContent && elem.getParentNode() != null) elem = (Element)elem.getParentNode();
            doc = keyCipher.doFinal(elem.getOwnerDocument(), elem, encByContent);    
        }
        
        saveXMLDocument(doc, outputFile);
    }

    private static void printHelp() {
        System.out.println("ENCRYPTION TOOL HELP");
        System.out.println("--------------------");
        System.out.println("-e    Encrypt mode [requires input/output files]");
        System.out.println("-d    Decrypt mode [requires input/output files]");
        System.out.println("-i    Input file");
        System.out.println("-o    Output file");
        System.out.println("-n    Nodes name. If specified, only encrypts the xml nodes matching this name");
        System.out.println("-c    Consider only element content encryption");
        System.out.println("--help    Displays this help");  
        System.out.println("--------------------");
    }

    private static Document getXMLDocument(String file) throws Exception {
        File xmlFile = new File(file);
        DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
        dbFactory.setNamespaceAware(true);
        DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
        Document doc = dBuilder.parse(xmlFile);
        return doc;
    }
    
    private static void saveXMLDocument(Document doc, String outputFile) throws TransformerException {
        TransformerFactory tranFactory = TransformerFactory.newInstance();
        Transformer aTransformer = tranFactory.newTransformer();
        Source src = new DOMSource(doc);
        Result dest = new StreamResult(new File(outputFile));
        aTransformer.transform(src, dest);
    }
    
    private static NodeList findXMLNodes(Document doc, String nodeName) throws Exception {
        try
        {
            XPathFactory xPathfactory = XPathFactory.newInstance();
            XPath xpath = xPathfactory.newXPath();
            XPathExpression expr = xpath.compile("//" + nodeName);
            return (NodeList) expr.evaluate(doc, XPathConstants.NODESET);
        }
        catch (XPathExpressionException ex) {
           throw ex;     
        }
    }
}
