package be.nabu.utils.security.basic;

import java.util.List;

import javax.jws.WebParam;
import javax.jws.WebResult;

public interface KeyStorePersistanceManager {
	public void set(@WebParam(name = "keystoreAlias") String keystoreAlias, @WebParam(name = "entryAlias") String entryAlias, @WebParam(name = "entry") KeyStoreEntry entry);
	@WebResult(name = "entry")
	public KeyStoreEntry get(@WebParam(name = "keystoreAlias") String keystoreAlias, @WebParam(name = "entryAlias") String entryAlias);
	@WebResult(name = "aliases")
	public List<String> getAliases(@WebParam(name = "keystoreAlias") String keystoreAlias);
	public void delete(@WebParam(name = "keystoreAlias") String keystoreAlias, @WebParam(name = "entryAlias") String entryAlias);
}
