global testtable : table[addr] of set[string] = table();

event http_header(c: connection,is_orig: bool, name: string, value: string) {
	 local source_ip: addr = c$id$orig_h;
	 if(name=="USER-AGENT")
	 {
            if(source_ip in testtable)
            {
                    if(!(to_lower(value) in testtable[source_ip]))
                    {
                            add testtable[source_ip][to_lower(value)];
                    }
            }
            else
            {
                    testtable[source_ip]=set(to_lower(value));
            }
	 }
    }
   
   event zeek_done(){
	for (source_ip, Set in testtable)
	{
		if(|Set|>=3)
		{
            print(addr_to_uri(source_ip) + " is a proxy");
		}
	}
}
