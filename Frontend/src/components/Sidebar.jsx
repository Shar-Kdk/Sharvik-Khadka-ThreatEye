import { Link, useLocation } from 'react-router-dom';

const Sidebar = ({ onLogout, isPlatformOwner }) => {
    const location = useLocation();

    const menuItems = isPlatformOwner ? [
        { name: 'Platform Overview', path: '/dashboard' },
        { name: 'Organizations', path: '/dashboard/organizations' },
        { name: 'Live Traffic', path: '/dashboard/live-traffic' }
    ] : [
        { name: 'Overview', path: '/dashboard' },
        { name: 'Subscription', path: '/dashboard/subscription' },
        { name: 'Live Traffic', path: '/dashboard/live-traffic' }
    ];

    return (
        <div className="w-64 bg-[#0d1117] border-r border-[#30363d] h-screen sticky top-0 flex flex-col">
            <div className="p-8">
                <h1 className="text-xl font-bold text-white tracking-tight">ThreatEye</h1>
            </div>

            <nav className="flex-grow px-4 space-y-1">
                {menuItems.map((item) => (
                    <Link
                        key={item.path}
                        to={item.path}
                        className={`block px-4 py-2.5 rounded-md text-sm font-medium transition-colors ${location.pathname === item.path
                            ? 'bg-[#1f2937] text-blue-400'
                            : 'text-gray-400 hover:bg-[#161b22] hover:text-white'
                            }`}
                    >
                        {item.name}
                    </Link>
                ))}
            </nav>

            <div className="p-6 border-t border-[#30363d]">
                <button
                    onClick={onLogout}
                    className="w-full flex items-center justify-center space-x-2 px-4 py-2.5 text-sm font-bold text-red-500 border border-red-500/30 rounded-lg hover:bg-red-500 hover:text-white transition-all duration-200 shadow-sm shadow-red-900/10"
                >
                    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" />
                    </svg>
                    <span>Logout</span>
                </button>
            </div>
        </div>
    );
};

export default Sidebar;
