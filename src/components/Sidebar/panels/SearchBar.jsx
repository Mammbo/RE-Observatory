import { useState } from 'react';
import Fuse from 'fuse.js';

// Search Bar component that searches with fuzzy finding from Fuse
const SearchBar = ({ data }) => { 
    const [query, setQuery] = useState('');
    const [results, setResults] = useState([]);
    const options = {
        keys: [
            // Imports
            'imports.name',
            'imports.address',
            // Exports
            'exports.name',
            'exports.address',
            // Strings - Static
            'strings.static.ascii',
            'strings.static.utf16',
            // Strings - Advanced
            'strings.advanced.stack',
            'strings.advanced.tight',
            // Strings - Obfuscated
            'strings.obfuscated.decode',
        ],
        includeScore: true,
        includeMatches: true,
        threshold: 0.3,
    }
    
    //init fuse - wrap data in array since Fuse expects an array
    const fuse = new Fuse(data ? [data] : [], options)

    const handleSearch = (event) => { 
        const value = event.target.value;
        setQuery(value);

        if (value.length === 0) {
            setResults([]);
            return;
        }

        const searchResults = fuse.search(value);
        setResults(searchResults);
    }

    return ( 
        <div> 
            <input
            type='text'
            placeholder='Search...'
            value={query}
            onChange={handleSearch}
            className='p-2 border rounded w-full'
        />
        {results.length  > 0 && ( 
            <ul className='mt-2 max-h-60 overflow-y-auto'>
            {results.map((result, resultIndex) => (
                result.matches.map((match, matchIndex) => (
                    <div key={`${resultIndex}-${matchIndex}`} className='flex justify-between p-2 hover:bg-gray-700 cursor-pointer max-h-50 overflow-y-auto overflow-x-hidden relative node-scrollbar'>
                        <span className='text-gray-400 justify-items-start gap-3'>
                            {match.key}:
                        </span>
                        <span>
                            {match.value}
                        </span>
                    </div>
                ))
            ))}
            </ul>
        )}
        </div>
    )
};

export default SearchBar; 
