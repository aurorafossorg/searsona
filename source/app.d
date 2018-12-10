import std.experimental.logger.core;

int main(string[] args) {
	//TODO: add an option handler
	import std.stdio : write, writeln;

	argType detectedType = detectArg(args[1]);
	if(detectedType==argType.WEB_URL)
		writeln("Web URL");
	else if(detectedType==argType.INET)
		writeln("IPv4");
	else if(detectedType==argType.INET6)
		writeln("IPv6");
	else if(detectedType==argType.DNS_HOST)
	{
		import std.socket;
		trace("Detected a possible DNS Host. Trying to resolve the address...");
		try {
			AddressInfo[] addrs = getAddressInfo(args[1], AddressInfoFlags.CANONNAME);
			trace("DNS Host is resolvable.");
			trace("Checking for canonical names...");
			writeln("Host: ", args[1]);
			foreach(AddressInfo addr; addrs)
			{
				//TODO: Not returning all canonical names
				if(addr.canonicalName != "" && addr.canonicalName != args[1])
					writeln("Canonical Name: ", addr.canonicalName);
			}
			trace("Checking for ip address associated...");
			addrs=getAddressInfo(args[1], SocketType.RAW);
			foreach(AddressInfo addr; addrs)
			{
				writeln("Address:", addr.address.toAddrString);
			}
		} catch(SocketOSException e) {
			info("Can't resolve DNS. Assuming unknwon query.");
		}
	}
	else if(detectedType==argType.EMAIL)
		writeln("Email");
	else if(detectedType==argType.NOSPACE_QUERY)
		writeln("Non spaced query");
	else
		writeln("Unknown query");
	return 0;
}

enum argType {
	WEB_URL,
	DNS_HOST,
	INET,
	INET6,
	EMAIL,
	NOSPACE_QUERY,
	UQUERY
}

argType detectArg(string arg)
{
	import std.regex : matchFirst, ctRegex;
	import std.string: indexOf;
	import std.net.isemail : isEmail;

	if(!matchFirst(arg, ctRegex!(`^(http|https)://`)).empty)
		return argType.WEB_URL;
	else if(!matchFirst(arg, ctRegex!(`^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$`)).empty)
		return argType.INET;
	else if(!matchFirst(arg, ctRegex!(`(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))`)).empty)
		return argType.INET6;
	else if(!matchFirst(arg, ctRegex!(`^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$`)).empty)
		return argType.DNS_HOST;
	else if(isEmail(arg))
		return argType.EMAIL;
	else if(indexOf(arg, ' ')==-1)
		return argType.NOSPACE_QUERY;

	return argType.UQUERY;
}