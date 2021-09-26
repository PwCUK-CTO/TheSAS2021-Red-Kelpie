/*
Copyright 2021 PwC UK

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

import "pe"
import "math"

rule Microsoft_Signed_DLL_With_High_Entropy_Data_After_Digital_Signature : Heuristic_and_General {

	meta:
		description = "Detects Windows signed DLLs that have had a payload encrypted and embedded in the digital signature section which is at least 50KB in size (seen by APT10 with its DESLoader/SigLoader campaigns)"
		TLP = "WHITE"
		author = "PwC Cyber Threat Operations :: BitsOfBinary"
		copyright = "Copyright PwC UK 2021 (C)"
		license = "Apache License, Version 2.0"
		created_date = "2021-02-19"
		modified_date = "2021-02-19"
		revision = "0"
		hash = "8ef94327cab01af04a83df86a662f3abe9ae35aa1084eff7273d8292941bebdb"
		hash = "69adaf19cc19594e0193da88597b6af886f1c0e148ad980fa0fe3f9250d52332"
		hash = "697be6add418ca9e1ebcef6cc6fdbb6277851e1892e48264b1e6720e48122c40"
		reference = "https://www.lac.co.jp/lacwatch/report/20201201_002363.html"

	strings:
		$timestamp = "Microsoft Time-Stamp PCA"

	condition:
		// Start with some initial conditions to rule out most samples (e.g. check that it's a DLL with one signature from Microsoft)
		uint16(0) == 0x5A4D and filesize < 1MB and (pe.characteristics & pe.DLL) and pe.number_of_signatures == 1 and for any sig in pe.signatures : (
			sig.subject contains "O=Microsoft Corporation" and
			sig.subject contains "CN=Microsoft Windows"
		) and
		// Sanity check that the timestamp string we're looking for is actually in the digital signature section
		// Throughout these next conditions, we only care about the last timestamp string, i.e. @timestamp[#timestamp]
		(
			@timestamp[#timestamp] > pe.data_directories[pe.IMAGE_DIRECTORY_ENTRY_SECURITY].virtual_address and
			@timestamp[#timestamp] < (pe.data_directories[pe.IMAGE_DIRECTORY_ENTRY_SECURITY].virtual_address + pe.data_directories[pe.IMAGE_DIRECTORY_ENTRY_SECURITY].size)
		) and
		// Check that the extra data at the end of the digital signature section is greater than roughly 5KB
		(
			pe.data_directories[pe.IMAGE_DIRECTORY_ENTRY_SECURITY].size - (@timestamp[#timestamp] - pe.data_directories[pe.IMAGE_DIRECTORY_ENTRY_SECURITY].virtual_address) > 5000
		) and
		// Extra check to make sure the entropy of this extra data is very high (i.e. encrypted)
		(
			math.entropy(@timestamp[#timestamp], (pe.data_directories[pe.IMAGE_DIRECTORY_ENTRY_SECURITY].size - (@timestamp[#timestamp] - pe.data_directories[pe.IMAGE_DIRECTORY_ENTRY_SECURITY].virtual_address))) > 6
		)
}

import "pe"
import "math"

rule Heuristic_Microsoft_Signed_PE_High_Entropy_Data_After_Digital_Signature : Heuristic_and_General
{
	meta:
		description = "Detects Windows signed DLLs that have high entropy data after the digital signature, potentially being an embedded payload. This is likely abuse of MS13-098, and has been seen used by APT10 and APT41 (although open source tools are now available to use this technique)"
		TLP = "WHITE"
		author = "PwC Cyber Threat Operations :: BitsOfBinary"
		copyright = "Copyright PwC UK 2021 (C)"
		license = "Apache License, Version 2.0"
		created_date = "2021-08-24"
		modified_date = "2021-08-24"
		revision = "0"
		reference = "https://github.com/med0x2e/SigFlip"
		hash = "697be6add418ca9e1ebcef6cc6fdbb6277851e1892e48264b1e6720e48122c40"
		hash = "adceda3c44ba816f5e8893c8e9923f32ea4f6cb1e6c4a3df1404196bf42eddfd"
		hash = "69adaf19cc19594e0193da88597b6af886f1c0e148ad980fa0fe3f9250d52332"

	strings:
		$timestamp = "Microsoft Time-Stamp PCA"

	condition:
		uint16(0) == 0x5A4D and
		for all sig in pe.signatures : (
			sig.subject contains "O=Microsoft Corporation" and
			sig.subject contains "CN=Microsoft"
		) and
		// Sanity check that the timestamp string we're looking for is actually in the digital signature section
		// Throughout these next conditions, we only care about the last timestamp string, i.e. @timestamp[#timestamp]
		(
			@timestamp[#timestamp] > pe.data_directories[pe.IMAGE_DIRECTORY_ENTRY_SECURITY].virtual_address and
			@timestamp[#timestamp] < (pe.data_directories[pe.IMAGE_DIRECTORY_ENTRY_SECURITY].virtual_address + pe.data_directories[pe.IMAGE_DIRECTORY_ENTRY_SECURITY].size)
		) and
		// Check that the extra data at the end of the digital signature section is greater than roughly 5KB
		(
			pe.data_directories[pe.IMAGE_DIRECTORY_ENTRY_SECURITY].size - (@timestamp[#timestamp] - pe.data_directories[pe.IMAGE_DIRECTORY_ENTRY_SECURITY].virtual_address) > 5000
		) and
		// Extra check to make sure the entropy of this extra data is very high (i.e. encrypted)
		(
			math.entropy(@timestamp[#timestamp], (pe.data_directories[pe.IMAGE_DIRECTORY_ENTRY_SECURITY].size - (@timestamp[#timestamp] - pe.data_directories[pe.IMAGE_DIRECTORY_ENTRY_SECURITY].virtual_address))) > 7
		)
}