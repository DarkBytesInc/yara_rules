rule Win_Downloader_Adload_133
{
strings:
	$a0 = { 3ee9bd054bafdd3642c6be662322b630c391857547d0f5b37c6ffbf774af4fb7d0e89320c7205e3e91a7bd75e1e3ad3be0e6b9b98cb941e7e74d1aff44910a38c42b03be7fb65446d0e575a649b13256f9299265745c0b75fbc7552605b20076273ebbf3c7fbc6bf0d5af6a4c3e296673c173a333f180102047e847d4b90a83e36f8b57124908c04f40090a0 }

condition:
	$a0
}

        