package iic

import (
	"crypto"
	"fmt"

	"github.com/beevik/etree"
	"github.com/noshto/dsig/pkg/safenet"
)

// Params represents collection of parameters needed for IIC function
type Params struct {
	SafenetConfig *safenet.Config
	InFile        string
	OutFile       string
}

// WriteIIC generates IIC from given parameters, writes it into the XML and saves to outFile
func WriteIIC(params *Params) error {
	// Load file
	doc := etree.NewDocument()
	if err := doc.ReadFromFile(params.InFile); err != nil {
		return err
	}

	// Parse parameters
	parsed, err := parse(doc)
	if err != nil {
		return err
	}

	// Generate
	IIC, IICSignature, err := GenerateIIC(params.SafenetConfig, parsed)
	if err != nil {
		return err
	}

	// Save
	doc.FindElement("//Invoice").RemoveAttr("IIC")
	doc.FindElement("//Invoice").CreateAttr("IIC", IIC)

	doc.FindElement("//Invoice").RemoveAttr("IICSignature")
	doc.FindElement("//Invoice").CreateAttr("IICSignature", IICSignature)

	doc.IndentTabs()
	doc.Root().SetTail("")

	err = doc.WriteToFile(params.OutFile)
	if err != nil {
		return err
	}
	return nil
}

// GenerateIIC generates IIC and IICSignature. Orders of parameters: TIN, IssueDateTime, InvOrdNum, BusinUnitCode, TCRCode, SoftCode, TotPrice
func GenerateIIC(SafenetConfig *safenet.Config, params [7]string) (string, string, error) {
	// Initialize Signer
	signer := safenet.SafeNet{}
	if err := signer.Initialize(SafenetConfig); err != nil {
		return "", "", err
	}
	defer signer.Finalize()

	plainIIC := fmt.Sprintf(
		"%v|%v|%v|%v|%v|%v|%v",
		params[0], // TIN
		params[1], // IssueDateTime
		params[2], // InvOrdNum
		params[3], // BusinUnitCode
		params[4], // TCRCode
		params[5], // SoftCode
		params[6], // TotPrice
	)
	fmt.Printf("Plain IIC: %s", plainIIC)

	hasher := crypto.SHA256.New()
	_, err := hasher.Write([]byte(plainIIC))
	if err != nil {
		return "", "", err
	}
	sha256IIC := hasher.Sum(nil)

	IICSignature, err := signer.SignPKCS1v15(sha256IIC)
	if err != nil {
		return "", "", err
	}
	hasher = crypto.MD5.New()
	_, err = hasher.Write(IICSignature)
	if err != nil {
		return "", "", err
	}
	IIC := hasher.Sum(nil)

	return fmt.Sprintf("%x", IIC), fmt.Sprintf("%x", IICSignature), err
}

// Parse retrieves values necessary for IIC generation from given doc
func parse(doc *etree.Document) ([7]string, error) {
	TIN, err := attributeOfElement("//Seller", "IDNum", doc)
	if err != nil {
		return [7]string{}, err
	}
	IssueDateTime, err := attributeOfElement("//Invoice", "IssueDateTime", doc)
	if err != nil {
		return [7]string{}, err
	}
	InvOrdNum, err := attributeOfElement("//Invoice", "InvOrdNum", doc)
	if err != nil {
		return [7]string{}, err
	}
	BusinUnitCode, err := attributeOfElement("//Invoice", "BusinUnitCode", doc)
	if err != nil {
		return [7]string{}, err
	}
	TCRCode, err := attributeOfElement("//Invoice", "TCRCode", doc)
	if err != nil {
		return [7]string{}, err
	}
	SoftCode, err := attributeOfElement("//Invoice", "SoftCode", doc)
	if err != nil {
		return [7]string{}, err
	}
	TotPrice, err := attributeOfElement("//Invoice", "TotPrice", doc)
	if err != nil {
		return [7]string{}, err
	}

	return [7]string{TIN, IssueDateTime, InvOrdNum, BusinUnitCode, TCRCode, SoftCode, TotPrice}, nil
}

// AttributeOfElement returns an attribute value if it's found in given element
func attributeOfElement(elemName string, attrName string, doc *etree.Document) (string, error) {
	return mapElement(elemName, doc, func(elem *etree.Element) (string, error) {
		return mapAttrib(attrName, elem, func(attr *etree.Attr) (string, error) {
			return attr.Value, nil
		})
	})
}

// MapElement returns element if it's found on given document
func mapElement(elemName string, doc *etree.Document, closure func(*etree.Element) (string, error)) (string, error) {
	elem := doc.FindElement(elemName)
	if elem == nil {
		return "", fmt.Errorf("can't find element %s", elemName)
	}
	return closure(elem)
}

// MapAttrib returns attribute value if it's found on given element
func mapAttrib(attrName string, elem *etree.Element, closure func(*etree.Attr) (string, error)) (string, error) {
	attr := elem.SelectAttr(attrName)
	if attr == nil {
		return "", fmt.Errorf("can't find attribute %s", attrName)
	}
	return closure(attr)
}
