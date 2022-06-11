import "pe"

rule IsNim : Nim{
  meta:  
		desc = "Identify windows Nim binaries (PE)"
		author = "Humoud Al Saleh"
		version = "1.0"
		last_modified = "11.06.2022"
  strings:
    $a1 = ".nim" ascii
  condition:
    pe.is_pe and $a1 and pe.characteristics & pe.LINE_NUMS_STRIPPED
}

// rule cpp_bin {

// }

// rule golang_bin {
//   condition:
//     pe.number_of_sections == 13
// }

// https://github.com/SentineLabs
// https://github.com/SentineLabs/AlphaGolang/blob/main/0.identify_go_binaries.yara
rule TTP_GoBuildID : Go
{
	meta:  
		desc = "Quick rule to identify Golang binaries (PE,ELF,Macho)"
		author = "JAG-S @ SentinelLabs"
		version = "1.0"
		last_modified = "10.06.2021"

	strings:
		$GoBuildId = /Go build ID: \"[a-zA-Z0-9\/_-]{40,120}\"/ ascii wide
	
	condition:
		(
			(uint16(0) == 0x5a4d) or 
			(uint32(0)==0x464c457f) or 
			(uint32(0) == 0xfeedfacf) or 
			(uint32(0) == 0xcffaedfe) or 
			(uint32(0) == 0xfeedface) or 
			(uint32(0) == 0xcefaedfe) 
		)
		and
		#GoBuildId == 1
}