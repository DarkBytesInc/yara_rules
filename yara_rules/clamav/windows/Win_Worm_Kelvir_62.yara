rule Win_Worm_Kelvir_62
{
strings:
	$a0 = { d4a45e24f155a23ea96ff668563e93bc8710486e196042a009ff400bf30b8642c560076393040c75b73ac011de24f785859d167251179f174664c4234a43818bf8c84182b3adc1b51fc48610ac5dfe52845865880fa9a0a66fd1df3c8133de1e27672d09110eb17299cf8d373615a4ce647ae426fd1a3c19f5ba0a329df2b8aa75c2a5e9ecfe891e682c5853 }

condition:
	$a0
}

        