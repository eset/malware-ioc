/*
The following rule requires YARA version >= 3.11.0
*/
import "pe"

rule RichHeaders_Lazarus_NukeSped_IconicPayloads_3CX_Q12023
{
	meta:
		description = "Rich Headers-based rule covering the IconicLoader and IconicStealer from the 3CX supply chain incident, and also payloads from the cryptocurrency campaigns from 2022-12"
		author = "ESET Research"
		date = "2023-03-31"
		hash = "3B88CDA62CDD918B62EF5AA8C5A73A46F176D18B"
		hash = "CAD1120D91B812ACAFEF7175F949DD1B09C6C21A"
		hash = "5B03294B72C0CAA5FB20E7817002C600645EB475"
		hash = "7491BD61ED15298CE5EE5FFD01C8C82A2CDB40EC"

	condition:
		pe.rich_signature.toolid(259, 30818) == 9 and
		pe.rich_signature.toolid(256, 31329) == 1 and
		pe.rich_signature.toolid(261, 30818) >= 30 and pe.rich_signature.toolid(261, 30818) <= 38  and
		pe.rich_signature.toolid(261, 29395) >= 134 and pe.rich_signature.toolid(261, 29395) <= 164  and
		pe.rich_signature.toolid(257, 29395) >= 6 and pe.rich_signature.toolid(257, 29395) <= 14 
}
