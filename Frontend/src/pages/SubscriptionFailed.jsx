import React, { useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';

const SubscriptionFailed = () => {
    const [searchParams] = useSearchParams();
    const [errorMsg, setErrorMsg] = useState('');

    useEffect(() => {
        const error = searchParams.get('error');
        if (error) {
            setErrorMsg(error);
        }
    }, [searchParams]);

    return (
        <div className="min-h-screen bg-gray-900 text-white flex items-center justify-center font-sans p-4">
            <div className="bg-gray-800 border border-gray-700 rounded-lg p-8 shadow-2xl max-w-md w-full text-center">

                <div className="bg-red-500/10 w-20 h-20 rounded-full flex items-center justify-center mx-auto mb-6">
                    <svg className="w-10 h-10 text-red-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M6 18L18 6M6 6l12 12"></path>
                    </svg>
                </div>

                <h1 className="text-3xl font-bold mb-4 text-white">Payment Failed</h1>

                <p className="text-gray-300 mb-8">
                    We were unable to process your payment. Please try again or contact support if the problem persists.
                </p>

                {errorMsg && (
                    <div className="bg-red-900/20 border border-red-900/50 rounded-lg p-4 mb-8 text-sm text-left">
                        <span className="text-red-400 font-bold block mb-1">Error Details:</span>
                        <span className="text-gray-300 font-mono break-words">{errorMsg}</span>
                    </div>
                )}

                <div className="flex flex-col space-y-3">
                    <a
                        href="/subscriptions/plans"
                        className="bg-blue-600 hover:bg-blue-700 text-white font-semibold py-3 px-4 rounded transition-colors duration-200"
                    >
                        Try Again
                    </a>
                    <a
                        href="/dashboard"
                        className="text-gray-400 hover:text-white font-medium py-2 transition-colors duration-200"
                    >
                        Return to Dashboard
                    </a>
                </div>
            </div>
        </div>
    );
};

export default SubscriptionFailed;