function Dashboard({ user, onLogout }) {
  return (
    <div className="min-h-screen bg-gray-900 text-white">
      <nav className="bg-gray-800 p-4 shadow-lg">
        <div className="container mx-auto flex justify-between items-center">
          <h1 className="text-2xl font-bold">ThreatEye Dashboard</h1>
          <button
            onClick={onLogout}
            className="bg-red-600 hover:bg-red-700 px-4 py-2 rounded"
          >
            Logout
          </button>
        </div>
      </nav>

      <div className="container mx-auto p-8">
        <div className="bg-gray-800 p-6 rounded-lg shadow-lg">
          <h2 className="text-xl font-bold mb-4">Welcome!</h2>
          <p className="text-gray-300">Email: {user.email}</p>
          <p className="text-gray-300">Name: {user.first_name} {user.last_name}</p>
          <p className="text-gray-400 text-sm mt-2">
            Account created: {new Date(user.date_joined).toLocaleDateString()}
          </p>
        </div>
      </div>
    </div>
  );
}

export default Dashboard;
