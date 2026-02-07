import { Link, useLocation } from 'react-router-dom';

const Sidebar = ({ isPlatformOwner }) => {
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
        </div>
    );
};

export default Sidebar;
