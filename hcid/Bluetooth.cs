/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2005-2006  Marcel Holtmann <marcel@holtmann.org>
 *
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

namespace Bluetooth
{
	using System;
	using DBus;

	[Interface("org.bluez.Manager")]
	internal abstract class ManagerProxy
	{
		[Method] public abstract string DefaultAdapter();
	}

	public delegate void RemoteDeviceFoundHandler(string address, Int16 rssi,
				string major, string minor, string[] services);
	public delegate void RemoteNameUpdatedHandler(string address, string name);

	[Interface("org.bluez.Adapter")]
	internal abstract class AdapterProxy
	{
		[Method] public abstract string GetAddress();
		[Method] public abstract string GetVersion();
		[Method] public abstract string GetRevision();
		[Method] public abstract string GetManufacturer();
		[Method] public abstract string GetCompany();

		[Method] public abstract void SetDiscoverableTimeout(int timeout);
		[Method] public abstract void SetMode(string mode);

		[Method] public abstract string GetName();
		[Method] public abstract void SetName(string name);
		[Method] public abstract string GetRemoteAlias(string address);
		[Method] public abstract void SetRemoteAlias(string address, string alias);

		[Method] public abstract string[] ListBondings();
		[Method] public abstract bool HasBonding(string address);

#pragma warning disable 0067
		[Signal] public virtual event RemoteDeviceFoundHandler RemoteDeviceFound;
		[Signal] public virtual event RemoteNameUpdatedHandler RemoteNameUpdated;
#pragma warning restore 0067
	}

	public class Adapter : IDisposable
	{
		private Service service;
		private Connection connection;
		private ManagerProxy manager;
		private AdapterProxy adapter;
		private string path;

#pragma warning disable 0067
		public event RemoteDeviceFoundHandler RemoteDeviceFound;
		public event RemoteNameUpdatedHandler RemoteNameUpdated;
#pragma warning restore 0067

		public Adapter() : this("")
		{
		}

		public Adapter(string path)
		{
			connection = Bus.GetSystemBus();
			service = Service.Get(connection, "org.bluez");

			manager = (ManagerProxy) service.GetObject(typeof(ManagerProxy), "/org/bluez");

			if (path == "")
				path = manager.DefaultAdapter();

			this.path = path;

			adapter = (AdapterProxy) service.GetObject(typeof(AdapterProxy), path);

			service.SignalCalled += OnSignalCalled;

			adapter.RemoteDeviceFound += OnRemoteDeviceFound;
			adapter.RemoteNameUpdated += OnRemoteNameUpdated;
		}

		public void Dispose()
		{
			GC.SuppressFinalize(adapter);
			GC.SuppressFinalize(manager);
		}

		private void OnSignalCalled(Signal signal)
		{
			if (signal.InterfaceName != "org.bluez.Adapter")
				return;

			if (signal.PathName != path)
				return;
		}

		private void OnRemoteDeviceFound(string address, Int16 rssi,
				string major, string minor, string[] services)
		{
			if (RemoteDeviceFound != null)
				RemoteDeviceFound(address, rssi, major, minor, services);
		}

		private void OnRemoteNameUpdated(string address, string name)
		{
			if (RemoteNameUpdated != null)
				RemoteNameUpdated(address, name);
		}

		public string Address {
			get { return adapter.GetAddress(); }
		}

		public string Version {
			get { return adapter.GetVersion(); }
		}

		public string Revision {
			get { return adapter.GetRevision(); }
		}

		public string Manufacturer {
			get { return adapter.GetManufacturer(); }
		}

		public string Company {
			get { return adapter.GetCompany(); }
		}

		public string Name {
			get { return adapter.GetName(); }
			set { adapter.SetName(value); }
		}

		public override string ToString() {
			return Address;
		}
	}
}
