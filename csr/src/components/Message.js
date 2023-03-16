import React, {Component} from "react";
import * as pkijs from "pkijs";
import * as asn1js from "asn1js";
import * as pvtsutils from "pvtsutils";

function formatPEM(pemString) {
    const PEM_STRING_LENGTH = pemString.length, LINE_LENGTH = 64;
    const wrapNeeded = PEM_STRING_LENGTH > LINE_LENGTH;
    if (wrapNeeded) {
        let formattedString = "", wrapIndex = 0;
        for (let i = LINE_LENGTH; i < PEM_STRING_LENGTH; i += LINE_LENGTH) {
            formattedString += pemString.substring(wrapIndex, i) + "\r\n";
            wrapIndex = i;
        }
        formattedString += pemString.substring(wrapIndex, PEM_STRING_LENGTH);
        return formattedString;
    }
    else {
        return pemString;
    }
}

function toPEM(buffer, tag) {
    return [
        `-----BEGIN ${tag}-----`,
        formatPEM(pvtsutils.Convert.ToBase64(buffer)),
        `-----END ${tag}-----`,
        "",
    ].join("\n");
}

async function createRequest(){
    const signAlg = 'ECDSA'
    const hashAlg = 'SHA-1'
    const pkcs10 = new pkijs.CertificationRequest();
    const crypto = pkijs.getCrypto(true);
    pkcs10.version = 0;
    pkcs10.subject.typesAndValues.push(new pkijs.AttributeTypeAndValue({
        type: "2.5.4.6",
        value: new asn1js.PrintableString({ value: "RU" })
    }));
    pkcs10.subject.typesAndValues.push(new pkijs.AttributeTypeAndValue({
        type: "2.5.4.3",
        value: new asn1js.Utf8String({ value: "Simple test" })
    }));
    const altNames = new pkijs.GeneralNames({
        names: [
            new pkijs.GeneralName({
                type: 1,
                value: "email@address.com"
            }),
            new pkijs.GeneralName({
                type: 2,
                value: "www.domain.com"
            }),
            new pkijs.GeneralName({
                type: 2,
                value: "www.anotherdomain.com"
            }),
            new pkijs.GeneralName({
                type: 7,
                value: new asn1js.OctetString({ valueHex: (new Uint8Array([0xC0, 0xA8, 0x00, 0x01])).buffer })
            }),
        ]
    });
    pkcs10.attributes = [];
    const algorithm = pkijs.getAlgorithmParameters(signAlg, "generateKey");
    // console.log(algorithm);
    // algorithm.algorithm.hash.name = 'SHA-1';
    // algorithm.algorithm.hashAlg  = 'SHA-1';
    const { privateKey, publicKey } = await crypto.generateKey(algorithm.algorithm, true, algorithm.usages);
    // console.log(privateKey);
    // console.log(publicKey);
    await pkcs10.subjectPublicKeyInfo.importKey(publicKey);
    const subjectKeyIdentifier = await crypto.digest({ name: "SHA-1" }, pkcs10.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHexView);
    pkcs10.attributes.push(new pkijs.Attribute({
        type: "1.2.840.113549.1.9.14",
        values: [(new pkijs.Extensions({
                extensions: [
                    new pkijs.Extension({
                        extnID: "2.5.29.14",
                        critical: false,
                        extnValue: (new asn1js.OctetString({ valueHex: subjectKeyIdentifier })).toBER(false)
                    }),
                    new pkijs.Extension({
                        extnID: "2.5.29.17",
                        critical: false,
                        extnValue: altNames.toSchema().toBER(false)
                    }),
                    new pkijs.Extension({
                        extnID: "1.2.840.113549.1.9.7",
                        critical: false,
                        extnValue: (new asn1js.PrintableString({ value: "passwordChallenge" })).toBER(false)
                    })
                ]
            })).toSchema()]
    }));
    await pkcs10.sign(privateKey, hashAlg);
    // console.log(formatPEM(pvtsutils.Convert.ToBase64(pkcs10.toSchema().toBER(false))));
    const buffer = pkcs10.toSchema().toBER(false);
    const tag = 'CERTIFICATE REQUEST';
    return toPEM(buffer, tag)
  

}
class Message extends Component{

    constructor(){
        super()
        this.state={
            message: 'CSR Request Generator'

        }
    }
    changeMessage(){

        const csrRequest =  createRequest();
        // this.setState({
        //     message: csrRequest
        // })

        console.log(csrRequest)
    }
    
    // async createRequest(){
    //     const signAlg = 'ECDSA'
    //     const hashAlg = 'SHA-1'
    //     const pkcs10 = new pkijs.CertificationRequest();
    //     const crypto = pkijs.getCrypto(true);
    //     pkcs10.version = 0;
    //     pkcs10.subject.typesAndValues.push(new pkijs.AttributeTypeAndValue({
    //         type: "2.5.4.6",
    //         value: new asn1js.PrintableString({ value: "RU" })
    //     }));
    //     pkcs10.subject.typesAndValues.push(new pkijs.AttributeTypeAndValue({
    //         type: "2.5.4.3",
    //         value: new asn1js.Utf8String({ value: "Simple test" })
    //     }));
    //     const altNames = new pkijs.GeneralNames({
    //         names: [
    //             new pkijs.GeneralName({
    //                 type: 1,
    //                 value: "email@address.com"
    //             }),
    //             new pkijs.GeneralName({
    //                 type: 2,
    //                 value: "www.domain.com"
    //             }),
    //             new pkijs.GeneralName({
    //                 type: 2,
    //                 value: "www.anotherdomain.com"
    //             }),
    //             new pkijs.GeneralName({
    //                 type: 7,
    //                 value: new asn1js.OctetString({ valueHex: (new Uint8Array([0xC0, 0xA8, 0x00, 0x01])).buffer })
    //             }),
    //         ]
    //     });
    //     pkcs10.attributes = [];
    //     const algorithm = pkijs.getAlgorithmParameters(signAlg, "generateKey");
    //     // console.log(algorithm);
    //     // algorithm.algorithm.hash.name = 'SHA-1';
    //     // algorithm.algorithm.hashAlg  = 'SHA-1';
    //     const { privateKey, publicKey } = await crypto.generateKey(algorithm.algorithm, true, algorithm.usages);
    //     // console.log(privateKey);
    //     // console.log(publicKey);
    //     await pkcs10.subjectPublicKeyInfo.importKey(publicKey);
    //     const subjectKeyIdentifier = await crypto.digest({ name: "SHA-1" }, pkcs10.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHexView);
    //     pkcs10.attributes.push(new pkijs.Attribute({
    //         type: "1.2.840.113549.1.9.14",
    //         values: [(new pkijs.Extensions({
    //                 extensions: [
    //                     new pkijs.Extension({
    //                         extnID: "2.5.29.14",
    //                         critical: false,
    //                         extnValue: (new asn1js.OctetString({ valueHex: subjectKeyIdentifier })).toBER(false)
    //                     }),
    //                     new pkijs.Extension({
    //                         extnID: "2.5.29.17",
    //                         critical: false,
    //                         extnValue: altNames.toSchema().toBER(false)
    //                     }),
    //                     new pkijs.Extension({
    //                         extnID: "1.2.840.113549.1.9.7",
    //                         critical: false,
    //                         extnValue: (new asn1js.PrintableString({ value: "passwordChallenge" })).toBER(false)
    //                     })
    //                 ]
    //             })).toSchema()]
    //     }));
    //     await pkcs10.sign(privateKey, hashAlg);
    //     // console.log(formatPEM(pvtsutils.Convert.ToBase64(pkcs10.toSchema().toBER(false))));
    //     const buffer = pkcs10.toSchema().toBER(false);
    //     const tag = 'CERTIFICATE REQUEST';
    //     console.log(toPEM(buffer, tag))

        
    
    // }
    render() {
        return (
            <div>
                <h1> {this.state.message} </h1>
                <button onClick={()=> this.changeMessage()}>Generate Request</button>
                <div>
                <textarea> </textarea>
                </div>
                
            </div>
            
        )
    }
}
export default Message;