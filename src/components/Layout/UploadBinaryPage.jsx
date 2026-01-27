// on upload run react hooks
// 
const UploadBinaryPage = ({ onSelectBinary, onSelectPreviousBinary}) => {
    return ( 
        <>
            <div className="min-h-screen w-full flex flex-col items-center justify-center space-y-4">
                 <button className="text-accent hover:text-accent-hover" onClick={onSelectBinary}>Upload a Binary</button>
                <button className="text-accent hover:text-accent-hover" onClick={onSelectPreviousBinary}>Examine an old Binary!</button>
            </div>
        </>
    );
}

export default UploadBinaryPage;
