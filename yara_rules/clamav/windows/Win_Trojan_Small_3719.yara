rule Win_Trojan_Small_3719
{
strings:
	$a0 = { a0dc7b1861f4f5c19f8c8d9673cc2503481429ae5f0feac6b58bfdeeafe28fafb2f40dc29f8c7a96d18f25aee2503eadd4b03dad759435ee5feb830bbbe5e804b7f425be5f8c8fb65ea15dbe9f8c75ad75c835ee5f17161960f64804ca8c24c4b39c65aee44c9ae0eac955be9f8c7bad3711e6 }

condition:
	$a0
}

        
