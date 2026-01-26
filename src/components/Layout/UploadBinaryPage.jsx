// on upload run react hooks
// 
const UploadBinaryPage = ({ onSelectBinary, onSelectPreviousBinary}) => {
    return ( 
        <>
            <button onClick={onSelectBinary}>Upload a Binary</button>
            <button onClick={onSelectPreviousBinary}>Examine an old Binary!</button>
        </>
    );
}

export default UploadBinaryPage;