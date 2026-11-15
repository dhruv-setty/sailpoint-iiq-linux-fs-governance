package io.github.whatheheckisthis.fsgov.config;

import org.w3c.dom.Document;
import org.xml.sax.InputSource;
import org.xml.sax.SAXParseException;
import org.xml.sax.helpers.DefaultHandler;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.StringReader;
import java.nio.file.Path;

/**
 * Hardened, non validating XML parsing. sailpoint.dtd ships inside
 * identityiq.war and is not available here, so external DTD loading is
 * switched off and the DOCTYPE is checked structurally instead. External
 * entities are disabled, so a file in config/ cannot read the build host.
 */
final class XmlSupport {

    private XmlSupport() {
    }

    static Document parse(Path file) throws Exception {
        DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
        f.setNamespaceAware(true);
        f.setValidating(false);
        f.setExpandEntityReferences(false);
        f.setXIncludeAware(false);
        f.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        f.setFeature("http://xml.org/sax/features/external-general-entities", false);
        f.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        f.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        f.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
        DocumentBuilder b = f.newDocumentBuilder();
        b.setEntityResolver((publicId, systemId) -> new InputSource(new StringReader("")));
        b.setErrorHandler(new DefaultHandler() {
            @Override
            public void error(SAXParseException e) throws SAXParseException {
                throw e;
            }

            @Override
            public void fatalError(SAXParseException e) throws SAXParseException {
                throw e;
            }
        });
        return b.parse(file.toFile());
    }
}
