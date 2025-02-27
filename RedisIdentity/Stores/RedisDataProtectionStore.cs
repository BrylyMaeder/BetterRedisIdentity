using AsyncRedisDocuments;
using Microsoft.AspNetCore.DataProtection.Repositories;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;

namespace BetterRedisIdentity.Stores
{
    public class RedisDataProtectionStore : IXmlRepository, IAsyncDocument
    {
        public string Id { get; set; }

        private AsyncDictionary<string, XElement> _elements => new(this);
        public RedisDataProtectionStore() 
        {
            Id = "dataProtection";
        }
        public IReadOnlyCollection<XElement> GetAllElements()
        {
            var task = _elements.GetAsync();
            task.Wait();

            return task.Result.Values;
        }

        public string IndexName()
        {
            return "identity";
        }

        public void StoreElement(XElement element, string friendlyName)
        {
            _elements.SetAsync(friendlyName, element);
        }
    }
}
