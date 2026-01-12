import React, { useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';

const SubscriptionSuccess = () => {
    const [searchParams] = useSearchParams();
    const [txnId, setTxnId] = useState('');

    useEffect(() => {
        const txn = searchParams.get('txn');
        if (txn) {
            setTxnId(txn);
        }
    }, [searchParams]);

    return (
        <div className="min-h-screen bg-gray-900 text-white flex items-center justify-center font-sans p-4">
            <div className="bg-gray-800 border border-gray-700 rounded-lg p-8 shadow-2xl max-w-md w-full text-center">

                <div className="bg-green-500/10 w-20 h-20 rounded-full flex items-center justify-center mx-auto mb-6">
                    <svg className="w-10 h-10 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7"></path>
                    </svg>
                </div>

                <h1 className="text-3xl font-bold mb-4 text-white">Payment Successful!</h1>

                <p className="text-gray-300 mb-8">
                    Thank you for subscribing to ThreatEye. Your monthly subscription is now active, significantly enhancing your security posture.
                </p>

                {txnId && (
                    <div className="bg-gray-700/50 rounded p-4 mb-8 text-sm break-all">
                        <span className="text-gray-400 block mb-1">Transaction ID:</span>
                        <span className="font-mono text-green-400">{txnId}</span>
                    </div>
                )}

                <a
                    href="/dashboard"
                    className="inline-block w-full bg-blue-600 hover:bg-blue-700 text-white font-semibold py-3 px-4 rounded transition-colors duration-200"
                >
                    Return to Dashboard
                </a>
            </div>
        </div>
    );
};

export default SubscriptionSuccess;