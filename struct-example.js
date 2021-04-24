// https://gitmemory.com/issue/node-ffi-napi/node-ffi-napi/64/611847202
// https://stackoverflow.com/questions/20835782/is-it-possible-to-create-an-array-of-structs-using-ref-struct-and-ref-array

const ref = require('ref-napi');
const StructType = require('ref-struct-di')(ref);

const MyStruct = StructType({
    a: 'int',
    b: 'int',
});

const myStructInstance = new MyStruct({
    a: 1,
    b: 2,
});

console.log(myStructInstance);

const buffer = myStructInstance.ref();

console.log(buffer);

buffer.type = MyStruct;
const x = buffer.deref();

console.log(ref.address(buffer));

console.log(myStructInstance.a);
console.log(myStructInstance.b);

console.log(x.a);
console.log(x.b);