rule Win_Spyware_Banker_2962
{
strings:
	$a0 = { e53f1e1880c366665d7c232886c71ba6b0412482e0d4d45f07bec49b6601741521d0ce21cb12c1875f51c9555de1a15729fd6c77d6bae0401b91d18fd9c4ed61836e852aa11117890c04cb1ce021126950264ccf637e6839637f45d721c2d89d369ed2156e9a1a1a0948706f6a1ff144d86a3e2845ddea38a13de0e732923c97ddb32471e404 }

condition:
	$a0
}

        