package com.soffid.iam.sync.agent2;

import java.rmi.RemoteException;
import java.util.List;

import com.soffid.iam.api.CustomObject;

import es.caib.seycon.ng.comu.Grup;
import es.caib.seycon.ng.comu.Rol;
import es.caib.seycon.ng.comu.Usuari;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.sync.intf.ExtensibleObject;

public class SSOActiveDirectoryAgent extends CustomizableActiveDirectoryAgent_v2 {

	public SSOActiveDirectoryAgent() throws RemoteException {
		super();
	}

	@Override
	public void updateUser(String userName, Usuari userData) throws RemoteException, InternalErrorException {
		// Nothing to do
	}

	@Override
	public void updateUser(String accountName, String description) throws RemoteException, InternalErrorException {
		// Nothing to do
	}

	@Override
	public void removeUser(String userName) throws RemoteException, InternalErrorException {
		// Nothing to do
	}

	@Override
	public void updateRole(Rol rol) throws RemoteException, InternalErrorException {
		// Nothing to do
	}

	@Override
	public void removeRole(String rolName, String dispatcher) throws RemoteException, InternalErrorException {
		// Nothing to do
	}

	@Override
	public void updateGroup(String key, Grup grup) throws RemoteException, InternalErrorException {
		// Nothing to do
	}

	@Override
	public void removeGroup(String key) throws RemoteException, InternalErrorException {
		// Nothing to do
	}

	@Override
	public void updateCustomObject(CustomObject obj) throws RemoteException, InternalErrorException {
		// Nothing to do
	}

	@Override
	public void removeCustomObject(CustomObject obj) throws RemoteException, InternalErrorException {
		// Nothing to do
	}

	@Override
	protected void updateObject(String accountName, String oldAccountName, ExtensibleObject object,
			ExtensibleObject source, List<String[]> changes, boolean enabled) throws Exception {
		// Nothing to do
	}
}
