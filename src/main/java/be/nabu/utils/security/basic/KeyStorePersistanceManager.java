package be.nabu.utils.security.basic;

import java.util.List;

import javax.jws.WebParam;
import javax.jws.WebResult;
// Important to note that keystores are case insensitive! If we add keys that have upper and lower case letters, they are all squashed to lowercase in jks/jceks keystores. Any provider must allow for case insenstive searching of aliases.
public interface KeyStorePersistanceManager {
	public void set(@WebParam(name = "keystoreAlias") String keystoreAlias, @WebParam(name = "entryAlias") String entryAlias, @WebParam(name = "entry") KeyStoreEntry entry);
	@WebResult(name = "entry")
	public KeyStoreEntry get(@WebParam(name = "keystoreAlias") String keystoreAlias, @WebParam(name = "entryAlias") String entryAlias);
	@WebResult(name = "aliases")
	public List<String> getAliases(@WebParam(name = "keystoreAlias") String keystoreAlias);
	@WebResult(name = "entries")
	public List<NamedKeyStoreEntry> getAll(@WebParam(name = "keystoreAlias") String keystoreAlias);
	public void delete(@WebParam(name = "keystoreAlias") String keystoreAlias, @WebParam(name = "entryAlias") String entryAlias);
}
