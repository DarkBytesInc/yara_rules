rule Win_Spyware_Banker_2935
{
strings:
	$a0 = { 8002a9c5de80be9abd49986153fc417ddb3bc16155dd3427acdb5e2b9cedfdbd6fd8eaba16ad4e7be5d621964acd5b78ea51fcef51e53dd8988e228a02a76c3e888a58c271d3bf7970fca3d78a976092d28c0e64d89c95318a7afb6e60bff4deb5d7014d1c814c12401253ecfa95 }

condition:
	$a0
}

        
