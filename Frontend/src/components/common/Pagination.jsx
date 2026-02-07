import React from 'react';

const Pagination = ({ 
    totalItems, 
    itemsPerPage, 
    currentPage, 
    onPageChange, 
    onItemsPerPageChange,
    itemsPerPageOptions = [5, 10, 20, 50]
}) => {
    const totalPages = Math.ceil(totalItems / itemsPerPage);
    
    if (totalPages <= 1 && totalItems <= itemsPerPageOptions[0]) return null;

    const renderPageNumbers = () => {
        const pages = [];
        const maxVisiblePages = 5;
        
        let startPage = Math.max(1, currentPage - Math.floor(maxVisiblePages / 2));
        let endPage = Math.min(totalPages, startPage + maxVisiblePages - 1);
        
        if (endPage - startPage + 1 < maxVisiblePages) {
            startPage = Math.max(1, endPage - maxVisiblePages + 1);
        }

        for (let i = startPage; i <= endPage; i++) {
            pages.push(
                <button
                    key={i}
                    onClick={() => onPageChange(i)}
                    className={`w-8 h-8 rounded border text-[10px] font-black transition-all duration-200 ${
                        currentPage === i 
                        ? 'bg-blue-600 border-blue-600 text-white shadow-lg shadow-blue-900/40' 
                        : 'border-[#30363d] text-gray-400 hover:bg-[#30363d] hover:text-white'
                    }`}
                >
                    {i}
                </button>
            );
        }
        return pages;
    };

    return (
        <div className="p-4 border-t border-[#30363d] bg-[#161b22]/30 flex items-center justify-between gap-4">
            <div className="flex items-center gap-3">
                <span className="text-[10px] text-gray-500 uppercase tracking-widest font-bold">Rows</span>
                <select
                    value={itemsPerPage}
                    onChange={(event) => {
                        const nextValue = Number(event.target.value);
                        if (Number.isFinite(nextValue) && nextValue > 0) {
                            onItemsPerPageChange(nextValue);
                        }
                    }}
                    className="bg-[#0d1117] border border-[#30363d] rounded-md px-2 py-1 text-[10px] font-bold text-gray-200 focus:outline-none focus:border-blue-500"
                >
                    {itemsPerPageOptions.map((option) => (
                        <option key={option} value={option}>
                            {option}
                        </option>
                    ))}
                </select>
                <span className="text-[10px] text-gray-500 font-bold">
                    Page {currentPage} / {totalPages}
                </span>
            </div>

            {/* Center: Pagination Controls */}
            <div className="flex items-center space-x-2 justify-center flex-1">
                <button
                    onClick={() => onPageChange(currentPage - 1)}
                    disabled={currentPage === 1}
                    className="p-2 rounded border border-[#30363d] text-gray-400 hover:bg-[#30363d] disabled:opacity-20 disabled:hover:bg-transparent transition-all group"
                    title="Previous Page"
                >
                    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M15 19l-7-7 7-7" />
                    </svg>
                </button>

                <div className="flex space-x-1">
                    {renderPageNumbers()}
                </div>

                <button
                    onClick={() => onPageChange(currentPage + 1)}
                    disabled={currentPage === totalPages}
                    className="p-2 rounded border border-[#30363d] text-gray-400 hover:bg-[#30363d] disabled:opacity-20 disabled:hover:bg-transparent transition-all group"
                    title="Next Page"
                >
                    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 5l7 7-7 7" />
                    </svg>
                </button>
            </div>

            <div className="text-[10px] text-gray-500 font-bold tabular-nums">
                {totalItems.toLocaleString()} total
            </div>
        </div>
    );
};

export default Pagination;
